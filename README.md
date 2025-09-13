# 🔐 Network Malware Detection — TrafficClassifier

Este projeto tem como objetivo aplicar um modelo supervisionado de aprendizado de máquina para detectar tráfego malicioso em redes, utilizando o algoritmo **Random Forest**. A abordagem envolve desde o pré-processamento dos dados até a avaliação do modelo com métricas robustas e curvas ROC.

## 📊 Visão Geral

O pipeline completo inclui:

- Carregamento eficiente dos dados com inferência de tipos
- Armazenamento em formato `.parquet` para otimização de desempenho
- Análise exploratória e tratamento de dados ausentes com `IterativeImputer`
- Engenharia de features para extrair padrões temporais e de tráfego
- Codificação de variáveis categóricas e filtragem de rótulos pouco representativos
- Redução de dimensionalidade com análise de correlação
- Treinamento e avaliação de modelo com métricas e curvas ROC

## 🧠 Modelo Utilizado

O classificador principal é o **RandomForestClassifier**, configurado com os seguintes hiperparâmetros:

- `n_estimators=200`
- `max_depth=30`
- `min_samples_split=10`
- `min_samples_leaf=5`
- `max_features='sqrt'`
- `class_weight='balanced'`

## Dicas

Em caso de algum erro no processo rode:

`pip install -r requirements.txt`


## Executando o notebook

A principio todo notebook esta automatizado, des do dowload dos arquivos até o resultado final.

## Fpipeline

O arquivo Fpipeline.py contém a implementação da classe TrafficClassifier, responsável por executar todas as etapas do pipeline de classificação de tráfego de rede malicioso. Ele foi projetado para ser modular, eficiente e facilmente reutilizável em diferentes conjuntos de dados com estrutura semelhante.

## Principais Funcionalidades

1. Pré-processamento de Dados

    Conversão de timestamps e limpeza de rótulos (label)

    Substituição de rótulos genéricos por rótulos detalhados

    Remoção de colunas irrelevantes e registros incompletos

    Codificação de protocolos (tcp, udp) e categorização de portas

    Criação de variáveis derivadas como byte_ratio, pkts_per_sec, burst_density, entre outras

2. Tratamento de Dados

    Imputação de valores ausentes com IterativeImputer (baseado em modelos estatísticos)

    Limitação de outliers com base em percentis (default: 95%)

3. Engenharia de Features

    Cálculo de correlação entre variáveis numéricas

    Remoção de atributos altamente correlacionados para evitar redundância e overfitting

    Codificação one-hot das categorias de portas de origem e destino

4. Treinamento e Avaliação

    Separação dos dados em treino e teste com estratificação

    Treinamento do modelo RandomForestClassifier com hiperparâmetros ajustados

    Avaliação com matriz de confusão e relatório de classificação

    Plotagem de curvas ROC para problemas binários ou multiclasse

## ▶️ Exemplo de Execução

```python
import pandas as pd
from Fpipeline import TrafficClassifier

# Carrega o dataset (ajuste o caminho conforme necessário)
df = pd.read_parquet("raw/dataset.parquet")

# Instancia o classificador
classifier = TrafficClassifier()

# Executa o pipeline completo
classifier.run_pipeline(df)

```

## ⚙️ Exemplo com Parâmetros Personalizados

```python

from Fpipeline import TrafficClassifier
import pandas as pd

# Carrega o dataset
df = pd.read_parquet("raw/dataset.parquet")

# Instancia o classificador com parâmetros customizados
classifier = TrafficClassifier(
    min_label_count=50,           # Reduz o mínimo de amostras por classe
    test_size=0.3,                # Usa 30% dos dados para teste
    random_state=123,            # Altera a semente para reprodutibilidade
    n_estimators=300,            # Aumenta o número de árvores
    max_depth=40,                # Permite árvores mais profundas
    min_samples_split=5,         # Divide com menos amostras
    min_samples_leaf=2,          # Permite folhas menores
    max_features='log2',         # Muda a estratégia de seleção de features
    class_weight=None            # Desativa balanceamento automático
)

# Executa o pipeline completo
classifier.run_pipeline(df)
```