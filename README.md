# ATous Secure Network 🛡️

**Uma plataforma de cibersegurança e comunicação autônoma, inteligente e resiliente para o ecossistema de IoT e redes distribuídas.**

📋 [Project Status](PROJECT_STATUS.md) | 📦 [Requirements](requirements.txt) | 📄 [License](LICENSE) | 🧪 [Testing Guide](tests/TESTING_APPROACH.md) | 🔌 [API Contracts](api-contracts.md)

-----

### **Visão Geral**

O **Atous Secure Network** é um framework de última geração que redefine a segurança e a comunicação em redes distribuídas. Projetado com uma abordagem TDD (Test-Driven Development), o sistema integra seis subsistemas sinérgicos para criar uma malha de dispositivos IoT que é:

  - 🧠 **Inteligente**: Utiliza IA e Aprendizado Federado para aprender e se adaptar a novas ameaças.
  - 🛡️ **Segura**: Combina detecção de anomalias comportamentais com um sistema de defesa bio-inspirado.
  - 🔗 **Resiliente**: Garante operação contínua com mecanismos de auto-recuperação (self-healing) em redes P2P.
  - ⚡ **Eficiente**: Otimiza dinamicamente a comunicação sem fio (LoRa) para o equilíbrio ideal entre performance e consumo de energia.

Este projeto não é apenas uma solução de segurança; é uma base para construir aplicações de IoT robustas, autônomas e preparadas para o futuro.

### ✨ **Principais Funcionalidades**

| Funcionalidade | Descrição |
| :--- | :--- |
| **Segurança Adaptativa (ABISS & NNIS)** | Detecção de ameaças em tempo real baseada em comportamento e um sistema de resposta que aprende e evolui, inspirado no sistema imunológico humano. |
| **Comunicação Otimizada (LoRa Optimizer)**| Ajuste dinâmico de parâmetros de redes LoRa para maximizar alcance, velocidade e eficiência energética, com conformidade para múltiplas regiões (BR, EU, US). |
| **Rede Auto-Recuperável (P2P Recovery)** | Detecção e mitigação automática de falhas de nós ("churn"), garantindo que a rede permaneça operacional mesmo com a perda de componentes. |
| **Inteligência Federada (Model Manager)** | Atualizações de modelos de IA de forma segura e distribuída (Over-The-Air) usando patches binários, garantindo privacidade e aprendizado contínuo na borda (Edge AI). |
| **Pipeline Cognitivo (LLM Integration)** | Uma ponte inovadora que permite que modelos de linguagem pequenos (SLM) nos dispositivos enviem "contextos" para um modelo grande (LLM) central, aprimorando a inteligência da rede sem expor dados brutos. |
| **Simulação de Hardware** | Suporte completo a mocks e stubs que permitem o desenvolvimento e teste de todo o sistema em ambientes sem hardware físico (Windows/Linux). |

### 💡 **Potencial de Mercado**

O Atous Secure Network é ideal para setores críticos que demandam alta segurança, resiliência e inteligência:

  - **Indústria 4.0**: Redes de sensores e atuadores em chão de fábrica.
  - **Cidades Inteligentes**: Infraestrutura urbana conectada (iluminação, tráfego, sensores ambientais).
  - **Agronegócio (AgroTech)**: Monitoramento de vastas áreas rurais com conectividade LoRa.
  - **Saúde Conectada (IoMT)**: Dispositivos de monitoramento de pacientes com foco em segurança e privacidade.
  - **Defesa e Segurança**: Redes de comunicação táticas e descentralizadas.

-----

### 🏗️ **Arquitetura e Diagramas do Sistema**

O sistema é construído sobre seis pilares que interagem para entregar uma solução completa e robusta.

#### **Diagrama 1: Arquitetura Geral de Alto Nível**

*Este diagrama mostra a interação sinérgica entre os seis subsistemas principais.*

```mermaid
graph TD
    subgraph "Camada de Inteligência e Orquestração"
        A[Model Manager]
        B[LLM Integration]
    end

    subgraph "Camada de Segurança Ativa"
        C[ABISS - Sistema de Detecção]
        D[NNIS - Sistema de Resposta]
    end

    subgraph "Camada de Rede e Comunicação"
        E[P2P Recovery System]
        F[LoRa Optimizer]
    end

    G[Dispositivos IoT / Nós da Rede]

    A -- "Gerencia e Atualiza Modelos" --> G
    B -- "Agrega Contexto e Aprimora Modelos" --> A
    C -- "Monitora Comportamento dos Nós" --> G
    C -- "Ameaça Detectada" --> D
    D -- "Aciona Resposta (ex: Isolar Nó)" --> E
    D -- "Atualiza Memória Imune" --> A
    E -- "Mantém a Rede Saudável" --> G
    F -- "Otimiza Comunicação" --> G
    G -- "Envia Dados de Comportamento e Métricas" --> C
    G -- "Envia Métricas de Canal" --> F
    G -- "Recebe Atualizações de Modelo" --> A

    classDef iot fill:#f9f,stroke:#333,stroke-width:2px;
    class G iot;
```

#### **Diagrama 2: Fluxograma de Detecção e Resposta a Ameaças (ABISS + NNIS)**

*Detalha o processo completo, desde a análise do comportamento de um nó até a resposta imune e o aprendizado.*

```mermaid
graph TD
    A[Início: Coleta de Dados do Nó] --> B{Análise pelo ABISS};
    B --> C[Geração de Perfil Comportamental];
    B --> D[Análise com IA - Gemma 3N];
    C --> E{Anomalia Detectada?};
    D --> E;
    E -- "Não" --> F[Fim: Comportamento Normal];
    E -- "Sim" --> G[Cálculo do Score de Ameaça];
    G --> H{Score > Threshold?};
    H -- "Não" --> I[Registra Evento de Baixo Risco];
    H -- "Sim" --> J[**Ameaça Confirmada**];
    J --> K[NNIS: Antígeno Identificado];
    K --> L{Célula de Memória Existe?};
    L -- "Sim" --> M[Resposta Rápida Pré-definida];
    L -- "Não" --> N[Geração de Nova Resposta Imune];
    N --> O{Tipo de Ação?};
    O -- "Bloquear IP" --> P[Ação: Isolar Nó / Bloquear IP];
    O -- "Rate Limit" --> Q[Ação: Limitar Conexões];
    O -- "Alerta" --> R[Ação: Notificar Administrador];
    P --> S[Avaliação da Eficácia da Resposta];
    Q --> S;
    R --> S;
    S --> T{Ameaça Neutralizada?};
    T -- "Sim" --> U[NNIS: Criar/Reforçar Célula de Memória];
    T -- "Não" --> V[ABISS: Reavaliar e Aprender com a Falha];
    U --> W[Fim do Ciclo];
    V --> W;
```

#### **Diagrama 3: Diagrama de Sequência da Atualização de Modelo OTA (Model Manager)**

*Ilustra como um nó na rede recebe uma atualização de modelo de forma segura e eficiente.*

```mermaid
sequenceDiagram
    participant Node as Nó na Rede
    participant MM as Model Manager
    participant Server as Servidor de Agregação/Coordenação

    loop Verificação Periódica
        Node->>MM: Verificar atualizações()
        MM->>Server: /model-version
        Server-->>MM: Resposta JSON (latest_version: 5)
        alt Nova versão disponível (5 > 4)
            MM->>Node: Nova versão (5) encontrada.
            Node->>MM: Solicitar patch de atualização.
            MM->>Server: /model-diff/4/5
            Server-->>MM: Patch binário (diff)
            MM->>Node: Aplicar patch()
            Node->>Node: Cria backup do modelo atual
            Node->>Node: Aplica o patch ao modelo
            alt Patch bem-sucedido
                Node-->>MM: Atualização Concluída (versão 5)
            else Falha na aplicação
                Node->>Node: Restaura o backup
                Node-->>MM: Erro na atualização, rollback realizado.
            end
        else Modelo já atualizado
            MM-->>Node: Nenhuma atualização necessária.
        end
    end
```

#### **Diagrama 4: Fluxograma de Recuperação de Falha de Nó (P2P Recovery)**

*Descreve como o sistema lida com a falha de um nó para manter a rede operacional.*

```mermaid
graph TD
    A[Início: Monitor de Saúde P2P] --> B{Nó 'N' responde ao Ping?};
    B -- "Sim" --> C[Atualiza Status: Nó 'N' Saudável];
    C --> A;
    B -- "Não" --> D[Incrementa Contador de Falhas para 'N'];
    D --> E{Contador > Max_Falhas?};
    E -- "Não" --> A;
    E -- "Sim" --> F[**Nó 'N' Declarado como Falho**];
    F --> G[Remove 'N' da Lista de Nós Ativos];
    G --> H[Aciona Redistribuição de Dados];
    H --> I[Nós vizinhos assumem os shards de dados de 'N'];
    G --> J[Aciona Reatribuição de Serviços];
    J --> K[Outro nó assume os serviços que 'N' executava];
    G --> L[Atualiza Tabelas de Roteamento da Rede];
    L --> M[Nós passam a ignorar 'N' nas rotas];
    M --> N[Fim: Rede Estabilizada sem o Nó 'N'];
    I --> N;
    K --> N;

    subgraph "Loop de Verificação de Recuperação"
        direction LR
        R1[Nó 'N' está na lista de falhos] --> R2{Tentar Ping novamente após Timeout?};
        R2 -- "Sim" --> R3{Nó 'N' responde?};
        R3 -- "Sim" --> R4[Nó 'N' Recuperado: Adiciona de volta aos ativos];
        R3 -- "Não" --> R5[Mantém na lista de falhos];
    end

    F --> R1;
```

#### **Diagrama 5: Diagrama de Fluxo de Dados da Pipeline Cognitiva (LLM-SLM) - CORRIGIDO**

*Ilustra a transferência de contexto entre os modelos de linguagem na borda e na nuvem para aprendizado aprimorado.*

```mermaid
graph TD
    subgraph "Dispositivo de Borda (Edge Device)"
        A["1. Dados Brutos (ex: logs de rede)"]
        B["2. SLM (Modelo Pequeno) local"]
        C["3. Geração de Contexto Cognitivo"]
        D["Payload Compacto e Anonimizado"]
    end

    subgraph "Servidor Central / Nuvem"
        E["5. Agregação de Contextos"]
        F["6. LLM (Modelo Grande) - Análise Profunda"]
        G["7. Geração de Insights e Atualizações"]
        H["8. Novas Assinaturas / Otimizações de Modelo"]
    end

    A -- "Processa" --> B
    B -- "Extrai Embeddings e Gera Resumo" --> C
    C -- "{embeddings, summary, metadata}" --> D
    D -- "4. Transmissão Segura (LoRa/Wi-Fi)" --> E
    E -- "Cria Prompt para Análise Agregada" --> F
    F -- "Identifica Padrões Globais" --> G
    G -- "Envia para o Model Manager" --> H
    H -- "9. Distribuição via OTA para os Nós" --> A

    classDef edge fill:#cce5ff,stroke:#333;
    class A,B,C,D edge;
    classDef cloud fill:#fff2cc,stroke:#333;
    class E,F,G,H cloud;
```

-----

### 🚀 **Início Rápido (Getting Started)**

#### **Pré-requisitos**

  - Python 3.8+
  - Git
  - Ambiente virtual (recomendado)

#### **1. Instalação**

```bash
# 1. Clone o repositório
git clone https://github.com/devrodts/Atous-Sec-Network.git
cd Atous-Sec-Network

# 2. Crie e ative o ambiente virtual
# No Windows
python -m venv venv
.\\venv\\Scripts\\Activate.ps1

# No Linux/macOS
python3 -m venv venv
source venv/bin/activate

# 3. Instale as dependências
# Para desenvolvimento em Windows (inclui mocks)
pip install -r requirements-dev-windows.txt

# Para produção ou Linux/Raspberry Pi
pip install -r requirements.txt
```

#### **2. Executando os Testes**

Para garantir que tudo está configurado corretamente, execute a suíte de testes completa.

```bash
# Execute todos os testes unitários com detalhes
python -m pytest tests/unit/ -v

# Gere um relatório de cobertura de código
python -m pytest --cov=atous_sec_network --cov-report=html
```

#### **3. Teste de Integração Rápido**

O projeto inclui um script de teste de integração que verifica a funcionalidade de todos os subsistemas principais em modo de simulação.

```bash
python test_integration.py
```

Você deverá ver uma saída indicando que **TODOS OS SISTEMAS ESTÃO OPERACIONAIS**.

### 📚 **Documentação Completa**

Para mais detalhes sobre cada módulo, configuração e guias de desenvolvimento, consulte a pasta `/docs`:

  - [**Guia de Iniciação**](https://www.google.com/search?q=./docs/getting-started/README.md)
  - [**Arquitetura do Sistema**](https://www.google.com/search?q=./docs/architecture/README.md)
  - [**Documentação da API**](https://www.google.com/search?q=./docs/technical/API_DOCUMENTATION.md)
  - [**Guia de Implantação (Deployment)**](https://www.google.com/search?q=./docs/deployment/README.md)

-----

### 🤝 **Como Contribuir**

Estamos abertos a contribuições\! Se você deseja participar:

1.  Faça um *fork* do repositório.
2.  Crie uma nova *branch* (`git checkout -b feature/sua-feature`).
3.  Desenvolva sua funcionalidade e escreva testes para ela.
4.  Garanta que todos os testes estão passando (`pytest`).
5.  Envie um *Pull Request* detalhado.

### 📄 **Licença**

Este projeto é licenciado sob os termos da licença **GNU General Public License v3.0**. Veja o arquivo [LICENSE](https://www.google.com/search?q=LICENSE) para mais detalhes.

-----

**Criado por Rodolfo Rodrigues - Atous Technology Systems**

*Agradecimentos: A toda família e amigos.*

*Criado com auxílio de múltiplas ferramentas como: Google, Gemini, Claude, Cursor, DeepSeek, e claro o nó humano aqui 🇧🇷*
