import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, OneHotEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.metrics import roc_curve, auc
import matplotlib.pyplot as plt
from sklearn.preprocessing import label_binarize
from sklearn.experimental import enable_iterative_imputer
from sklearn.impute import IterativeImputer

class TrafficClassifier:
    def __init__(self, min_label_count=100, test_size=0.2, random_state=42,
                n_estimators=200, max_depth=30, min_samples_split=10,
                min_samples_leaf=5, max_features='sqrt', class_weight='balanced'):
    
        self.min_label_count = min_label_count
        self.test_size = test_size
        self.random_state = random_state
        self.label_encoder = LabelEncoder()
        self.port_encoder = OneHotEncoder(drop='first', sparse_output=False, handle_unknown='ignore')
        
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            min_samples_split=min_samples_split,
            min_samples_leaf=min_samples_leaf,
            max_features=max_features, # type: ignore
            class_weight=class_weight, # type: ignore
            random_state=random_state,
            n_jobs=-1
        )

    def imputar_dados(self,df, colunas, min_val=0, posterior=True, iteracoes=10):
        imputer = IterativeImputer(
            initial_strategy = 'most_frequent',
            random_state=42,
            max_iter=iteracoes,
            sample_posterior=posterior,
            min_value=min_val
        )
        
        df[colunas] = df[colunas].astype(float)
        df[colunas] = imputer.fit_transform(df[colunas])
        
        return df
    def limitar_outliers(self,df, cols=None, limite_percentil=0.95):
        df_limpo = df.copy()
        
        # Se nenhuma coluna for especificada, aplica em todas numéricas
        if cols is None:
            cols = df.select_dtypes(include='number').columns.tolist()
        
        for col in cols:
            limite = df[col].quantile(limite_percentil)
            df_limpo[col] = df[col].clip(upper=limite)
    
        return df_limpo
    
    def categorize_port(self, port):
        if pd.isna(port): return 'unknown'
        elif port <= 1023: return 'well_known'
        elif port <= 49151: return 'registered'
        elif port <= 65535: return 'dynamic'
        else: return 'invalid'

    def preprocess(self, df):
        # Timestamp and label cleanup
        df['ts'] = pd.to_datetime(df['ts'], unit='s')
        df['label'] = df['label'].str.strip()
        df.loc[df['label'] == 'Malicious', 'label'] = df.loc[df['label'] == 'Malicious', 'detailed-label']
        df['label'] = df['label'].str.replace(r'^Malicious\s*', '', regex=True)
        df.drop(columns='detailed-label', inplace=True)

        # Feature engineering
        df['log_duration'] = np.log1p(df['duration'])
        df['conn_count'] = df.groupby('id.orig_h')['uid'].transform('count')
        df = df.sort_values(by=['id.orig_h', 'ts'])
        df['iat'] = df.groupby('id.orig_h')['ts'].diff().dt.total_seconds()
        host_times = df.groupby('id.orig_h')['ts'].agg(['min', 'max'])
        df = df.merge((host_times['max'] - host_times['min']).dt.total_seconds().rename('active_duration'), on='id.orig_h', how='left')

        # Drop irrelevant columns
        df.drop(columns=[
            'service', 'tunnel_parents', 'uid', 'ts', 'id.orig_h', 'id.resp_h',
            'local_orig', 'local_resp', 'conn_state', 'history'
        ], inplace=True)

        # Drop rows with missing critical values
        df.dropna(subset=['duration', 'orig_bytes', 'resp_bytes'], inplace=True)

        # Filter labels with enough samples
        labels_to_keep = df['label'].value_counts()[lambda x: x >= self.min_label_count].index
        df = df[df['label'].isin(labels_to_keep)].copy()

        # Protocol encoding
        df = df[df['proto'].isin(['tcp', 'udp'])]
        df['protocol_encoded'] = df['proto'].map({'tcp': 0, 'udp': 1})
        df.drop(columns='proto', inplace=True)

        # Port categorization
        df['orig_port_cat'] = df['id.orig_p'].apply(self.categorize_port)
        df['resp_port_cat'] = df['id.resp_p'].apply(self.categorize_port)
        df.drop(columns=['id.orig_p', 'id.resp_p'], inplace=True)

        # Derived features
        df['byte_ratio'] = df['orig_bytes'] / (df['resp_bytes'] + 1)
        df['pkt_ratio'] = df['orig_pkts'] / (df['resp_pkts'] + 1)
        df['ip_byte_ratio'] = df['orig_ip_bytes'] / (df['resp_ip_bytes'] + 1)
        df['bytes_per_sec'] = (df['orig_bytes'] + df['resp_bytes']) / (df['duration'] + 0.001)
        df['pkts_per_sec'] = (df['orig_pkts'] + df['resp_pkts']) / (df['duration'] + 0.001)
        df['is_unidirectional'] = ((df['orig_bytes'] > 0) & (df['resp_bytes'] == 0)).astype(int)
        df['missed_ratio'] = df['missed_bytes'] / (df['orig_bytes'] + df['resp_bytes'] + 1)
        df['burst_density'] = df['conn_count'] / (df['active_duration'] + 1)
        df['pkt_intensity'] = df['pkts_per_sec'] * df['is_unidirectional']

        # Encode labels
        df['label_encoded'] = self.label_encoder.fit_transform(df['label'])

        return df
    
    def prepare_data(self, df,threshold=0.95):
        # Drop unused columns
        df_numeric = df.select_dtypes(include=[np.number])

        # Calcula a matriz de correlação absoluta
        corr_matrix = df_numeric.corr().abs()

        # Cria máscara para parte superior da matriz
        upper_tri = corr_matrix.where(np.triu(np.ones(corr_matrix.shape), k=1).astype(bool))

        # Identifica colunas com correlação acima do limite
        Todrop = [column for column in upper_tri.columns if any(upper_tri[column] > threshold)]
        
        labels = ['label', 'label_encoded','orig_port_cat', 'resp_port_cat']

        for label in labels:
            Todrop.append(label)

        X_raw = df.drop(columns=Todrop)
        y = df['label_encoded']

        # Train/test split
        X_train_raw, X_test_raw, y_train, y_test = train_test_split(
            X_raw, y, test_size=self.test_size, stratify=y, random_state=self.random_state
        )

        # One-hot encode port categories
        encoded_train = self.port_encoder.fit_transform(df.loc[X_train_raw.index, ['orig_port_cat', 'resp_port_cat']])
        encoded_test = self.port_encoder.transform(df.loc[X_test_raw.index, ['orig_port_cat', 'resp_port_cat']])

        encoded_train_df = pd.DataFrame(encoded_train, columns=self.port_encoder.get_feature_names_out(['orig_port_cat', 'resp_port_cat']), index=X_train_raw.index)
        encoded_test_df = pd.DataFrame(encoded_test, columns=self.port_encoder.get_feature_names_out(['orig_port_cat', 'resp_port_cat']), index=X_test_raw.index) # type: ignore

        # Combine encoded features
        X_train = pd.concat([X_train_raw.reset_index(drop=True), encoded_train_df.reset_index(drop=True)], axis=1)
        X_test = pd.concat([X_test_raw.reset_index(drop=True), encoded_test_df.reset_index(drop=True)], axis=1)

        return X_train, X_test, y_train, y_test



    def plot_roc_curve(self, X_test, y_test):
        """
        Plota a curva ROC para classificação binária ou multiclasse.
        """
        y_score = self.model.predict_proba(X_test)

        # Verifica se é binário ou multiclasse
        n_classes = y_score.shape[1]

        if n_classes == 2:
            # Binário
            fpr, tpr, _ = roc_curve(y_test, y_score[:, 1])
            roc_auc = auc(fpr, tpr)

            plt.figure(figsize=(8, 6))
            plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (AUC = {roc_auc:.2f})')
            plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
            plt.xlabel('False Positive Rate')
            plt.ylabel('True Positive Rate')
            plt.title('Curva ROC - Binária')
            plt.legend(loc='lower right')
            plt.grid(True)
            plt.show()

        else:
            # Multiclasse
            y_test_bin = label_binarize(y_test, classes=np.unique(y_test))

            plt.figure(figsize=(10, 8))
            for i in range(n_classes):
                fpr, tpr, _ = roc_curve(y_test_bin[:, i], y_score[:, i]) # type: ignore
                roc_auc = auc(fpr, tpr)
                label_name = self.label_encoder.inverse_transform([i])[0]
                plt.plot(fpr, tpr, lw=2, label=f'{label_name} (AUC = {roc_auc:.2f})')

            plt.plot([0, 1], [0, 1], 'k--', lw=2)
            plt.xlabel('False Positive Rate')
            plt.ylabel('True Positive Rate')
            plt.title('Curvas ROC - Multiclasse')
            plt.legend(loc='lower right')
            plt.grid(True)
            plt.show()

    def train(self, X_train, y_train):
        self.model.fit(X_train, y_train)

    def evaluate(self, X_test, y_test):
        y_pred = self.model.predict(X_test)
        print(confusion_matrix(y_test, y_pred))
        print(classification_report(y_test, y_pred, target_names=self.label_encoder.classes_))


    def run_pipeline(self, df,threshold=0.95):
        df = self.imputar_dados(df,['duration', 'orig_bytes','resp_bytes'])
        df = self.limitar_outliers(df)
        df = self.preprocess(df)
        X_train, X_test, y_train, y_test = self.prepare_data(df,threshold=0.95)
        self.train(X_train, y_train)
        self.evaluate(X_test, y_test)
        self.plot_roc_curve(X_test,y_test)
