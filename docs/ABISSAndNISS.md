```mermaid
graph TD
    subgraph "ENTRADA DE DADOS"
        IOT1[No IoT A<br/>CPU: 45%, RAM: 67%<br/>Conexoes: 23/min]
        IOT2[No IoT B<br/>CPU: 89%, RAM: 94%<br/>Conexoes: 157/min]
        IOT3[No IoT C<br/>CPU: 23%, RAM: 45%<br/>Conexoes: 12/min]
    end

    subgraph "ABISS - ADAPTIVE BEHAVIORAL INTELLIGENCE SECURITY SYSTEM"
        subgraph "Analise Comportamental"
            COLLECT[Data Collector<br/>• Metricas de sistema<br/>• Padroes de rede<br/>• Comportamento aplicacoes]
            PROFILE[Behavioral Profiler<br/>• Perfil normal do no<br/>• Historico comportamental<br/>• Padroes temporais]
        end
        
        subgraph "Inteligencia Artificial"
            GEMMA[Gemma 3N AI Engine<br/>• Analise de padroes<br/>• Deteccao de anomalias<br/>• Classificacao de ameacas]
            ANOMALY[Anomaly Detector<br/>• Desvios comportamentais<br/>• Analise estatistica<br/>• Correlacao temporal]
        end
        
        subgraph "Sistema de Pontuacao"
            SCORER[Threat Scorer<br/>Score: 0-100<br/>Severity Classification]
            THRESHOLD[Dynamic Threshold<br/>Adaptativo por contexto<br/>Threshold atual: 75]
            VALIDATOR[False Positive Filter<br/>• Validacao cruzada<br/>• Contexto temporal<br/>• Padroes conhecidos]
        end
    end

    subgraph "NNIS - NEURAL NETWORK IMMUNE SYSTEM"
        subgraph "Sistema Imunologico Bio-Inspirado"
            ANTIGEN[Antigen Identifier<br/>• Classifica tipo de ameaca<br/>• Assinatura unica<br/>• Caracteristicas maliciosas]
            
            MEMORY[Immune Memory Bank<br/>┌─ Celula Mem A: DDoS ─┐<br/>│ Resposta: Rate Limit │<br/>│ Eficacia: 94%       │<br/>└─────────────────────┘<br/>┌─ Celula Mem B: Malware ┐<br/>│ Resposta: Isolamento  │<br/>│ Eficacia: 87%        │<br/>└───────────────────────┘]
        end
        
        subgraph "Gerador de Resposta"
            PRIMARY[Primary Response<br/>• Primeira exposicao<br/>• Resposta experimental<br/>• Aprendizado ativo]
            
            SECONDARY[Secondary Response<br/>• Resposta conhecida<br/>• Execucao rapida<br/>• Alta eficiencia]
            
            ADAPTIVE[Adaptive Response<br/>• Mutacao de resposta<br/>• Melhoria continua<br/>• Evolucao da estrategia]
        end
        
        subgraph "Executor de Acoes"
            ISOLATE[Node Isolation<br/>• Remove da rede<br/>• Quarentena temporaria<br/>• Analise forense]
            
            LIMIT[Rate Limiting<br/>• Limita conexoes<br/>• Throttling de dados<br/>• Controle de fluxo]
            
            BLOCK[IP Blocking<br/>• Blacklist dinamica<br/>• Bloqueio geografico<br/>• Filtragem de pacotes]
            
            ALERT[Alert System<br/>• Notificacao admin<br/>• Log de seguranca<br/>• Dashboard atualizado]
        end
    end

    subgraph "SISTEMA DE APRENDIZADO"
        EVALUATE[Response Evaluator<br/>• Mede eficacia da acao<br/>• Monitora resolucao<br/>• Coleta feedback]
        
        LEARNING[Learning Engine<br/>• Reforca respostas eficazes<br/>• Cria novas celulas de memoria<br/>• Atualiza thresholds]
        
        EVOLUTION[System Evolution<br/>• Melhoria dos algoritmos<br/>• Otimizacao de respostas<br/>• Adaptacao a novas ameacas]
    end

    %% Fluxo de Dados ABISS
    IOT1 --> COLLECT
    IOT2 --> COLLECT
    IOT3 --> COLLECT
    
    COLLECT --> PROFILE
    COLLECT --> GEMMA
    
    PROFILE --> ANOMALY
    GEMMA --> ANOMALY
    
    ANOMALY --> SCORER
    SCORER --> THRESHOLD
    THRESHOLD --> VALIDATOR

    %% Decisao ABISS → NNIS
    VALIDATOR --> |Score > 75<br/>Ameaca Confirmada| ANTIGEN
    VALIDATOR --> |Score ≤ 75<br/>Comportamento Normal| COLLECT

    %% Fluxo NNIS - Sistema Imunologico
    ANTIGEN --> MEMORY
    
    MEMORY --> |Ameaca Conhecida<br/>Celula de Memoria Existe| SECONDARY
    MEMORY --> |Ameaca Desconhecida<br/>Nova Ameaca| PRIMARY
    
    SECONDARY --> |Resposta Rapida| ISOLATE
    SECONDARY --> |Resposta Rapida| LIMIT
    SECONDARY --> |Resposta Rapida| BLOCK
    SECONDARY --> |Resposta Rapida| ALERT
    
    PRIMARY --> |Resposta Experimental| ISOLATE
    PRIMARY --> |Resposta Experimental| LIMIT
    PRIMARY --> |Resposta Experimental| BLOCK
    PRIMARY --> |Resposta Experimental| ALERT
    
    %% Sistema de Aprendizado
    ISOLATE --> EVALUATE
    LIMIT --> EVALUATE
    BLOCK --> EVALUATE
    ALERT --> EVALUATE
    
    EVALUATE --> LEARNING
    LEARNING --> EVOLUTION
    EVOLUTION --> MEMORY
    
    %% Feedback Loop
    EVALUATE --> |Feedback| COLLECT
    EVOLUTION --> |Novos Padroes| PROFILE

## Descricao do Sistema

### ABISS - Sistema de Inteligencia Comportamental Adaptativa

O **ABISS** (Adaptive Behavioral Intelligence Security System) e o cerebro do sistema de seguranca, responsavel por:

1. **Coleta de Dados**: Monitora continuamente todos os nos IoT e suas metricas
2. **Perfilamento Comportamental**: Cria e mantem perfis normais para cada no
3. **Detecao de Anomalias**: Usa IA (Gemma 3N) para identificar desvios comportamentais
4. **Sistema de Pontuacao**: Avalia ameacas em escala de 0-100 com thresholds adaptativos
5. **Filtro de Falsos Positivos**: Valida ameacas antes de acionar respostas

### NNIS - Sistema Imunologico Neural

O **NNIS** (Neural Network Immune System) implementa respostas de seguranca inspiradas no sistema imunologico humano:

1. **Identificacao de Antigenos**: Classifica tipos de ameacas
2. **Memoria Imunologica**: Armazena respostas eficazes para ameacas conhecidas
3. **Geracao de Respostas**: 
   - **Primaria**: Para ameacas desconhecidas (experimental)
   - **Secundaria**: Para ameacas conhecidas (rapida e eficiente)
   - **Adaptativa**: Evolui e melhora respostas existentes
4. **Executor de Acoes**: Implementa medidas de seguranca (isolamento, rate limiting, bloqueio)

### Sistema de Aprendizado

O sistema aprende continuamente com cada interacao:

1. **Avaliacao**: Mede a eficacia de cada acao tomada
2. **Aprendizado**: Reforca estrategias bem-sucedidas
3. **Evolucao**: Otimiza algoritmos e cria novas estrategias

### Fluxo de Operacao

1. **Coleta**: Dados sao coletados de todos os nos IoT
2. **Analise**: ABISS analisa comportamentos e detecta anomalias
3. **Decisao**: Se score > 75, ameaca e confirmada e enviada para NNIS
4. **Resposta**: NNIS executa acao apropriada baseada na memoria imunologica
5. **Avaliacao**: Sistema avalia eficacia da resposta
6. **Aprendizado**: Conhecimento e incorporado para futuras ameacas

Este sistema proporciona seguranca adaptativa, auto-aprendizagem e resposta rapida a ameacas conhecidas, enquanto mantem capacidade de lidar com ameacas desconhecidas de forma experimental.