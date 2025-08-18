# 🧠 **Sistema LLM ATous Secure Network - Guia Completo**

## 📋 **Visão Geral**

O sistema LLM da ATous Secure Network integra o modelo **Gemma 3N** para fornecer inteligência artificial avançada à plataforma. Este sistema é capaz de:

- **Responder perguntas** sobre o sistema de segurança
- **Analisar dados** em tempo real
- **Realizar fine-tuning** automático do sistema
- **Fornecer assistência** técnica e insights
- **Otimizar parâmetros** de segurança automaticamente

## 🚀 **Funcionalidades Principais**

### **1. Assistente Virtual Inteligente**
- **Consultas sobre o sistema**: Status, métricas, configurações
- **Análise de segurança**: Ameaças, vulnerabilidades, padrões
- **Assistência técnica**: Configuração, otimização, troubleshooting
- **Insights automáticos**: Recomendações baseadas em dados

### **2. Fine-Tuning Automático**
- **Otimização diária** dos thresholds de segurança
- **Ajuste automático** de parâmetros ABISS/NNIS
- **Melhoria contínua** baseada em dados reais
- **Validação de performance** e métricas

### **3. Integração com Sistema**
- **Acesso direto** aos dados de segurança
- **Contexto em tempo real** do sistema
- **Análise de logs** e métricas
- **Respostas contextualizadas** e precisas

## 🔌 **Endpoints da API**

### **REST API**

#### **POST `/api/llm/query`**
**Consultar o LLM com uma pergunta**

```json
{
  "question": "Quais foram as últimas ameaças bloqueadas pelo sistema?",
  "context": {
    "include_security_data": true,
    "include_user_stats": true
  },
  "include_system_context": true
}
```

**Resposta:**
```json
{
  "answer": "Com base nos dados do sistema, foram bloqueadas 15 ameaças nas últimas 24 horas...",
  "confidence": 0.85,
  "sources": ["llm", "abiss", "system_metrics"],
  "metadata": {
    "question_type": "security_threat",
    "response_length": 245,
    "has_context": true
  },
  "timestamp": "2025-01-17T20:30:00Z",
  "processing_time": 1.23
}
```

#### **POST `/api/llm/fine-tuning`**
**Iniciar fine-tuning manual**

```json
{
  "force": false
}
```

**Resposta:**
```json
{
  "success": true,
  "improvements": {
    "abiss_threshold": 0.02,
    "nnis_sensitivity": 0.03,
    "response_time": 0.05
  },
  "new_thresholds": {
    "abiss_threat_threshold": 0.93,
    "nnis_threat_threshold": 0.92,
    "rate_limit_threshold": 0.85
  },
  "training_loss": 0.15,
  "timestamp": "2025-01-17T20:30:00Z",
  "message": "Fine-tuning concluído com sucesso"
}
```

#### **GET `/api/llm/status`**
**Status do serviço LLM**

**Resposta:**
```json
{
  "is_loaded": true,
  "is_training": false,
  "model_path": "models/gemma-3n/extracted",
  "metrics": {
    "total_queries": 150,
    "successful_responses": 148,
    "average_response_time": 1.45,
    "cache_size": 45,
    "is_loaded": true,
    "is_training": false
  },
  "last_fine_tuning": "2025-01-17T18:00:00Z"
}
```

#### **POST `/api/llm/load-model`**
**Carregar modelo manualmente**

**Resposta:**
```json
{
  "message": "Modelo carregado com sucesso"
}
```

#### **GET `/api/llm/context`**
**Contexto atual do sistema**

**Resposta:**
```json
{
  "timestamp": "2025-01-17T20:30:00Z",
  "system_status": "operational",
  "abiss": {
    "status": "active",
    "threats_blocked": 15,
    "total_requests": 1250
  },
  "nnis": {
    "status": "active",
    "immune_cells": 45,
    "memory_cells": 120
  },
  "users": {
    "total": 25,
    "active": 23,
    "recent": 3
  }
}
```

### **WebSocket API**

#### **WebSocket `/api/llm/ws`**
**Comunicação em tempo real com o LLM**

**Mensagens de entrada:**

1. **Consulta:**
```json
{
  "type": "query",
  "question": "Como está o sistema de segurança hoje?",
  "context": {
    "include_performance_metrics": true
  }
}
```

2. **Fine-tuning:**
```json
{
  "type": "fine_tuning",
  "force": false
}
```

3. **Ping:**
```json
{
  "type": "ping"
}
```

**Mensagens de saída:**

1. **Boas-vindas:**
```json
{
  "type": "welcome",
  "message": "Conectado ao assistente LLM da ATous Secure Network",
  "timestamp": "2025-01-17T20:30:00Z",
  "capabilities": [
    "Consultas sobre o sistema",
    "Análise de segurança",
    "Assistência técnica",
    "Fine-tuning automático"
  ]
}
```

2. **Processando:**
```json
{
  "type": "processing",
  "message": "Processando sua pergunta...",
  "timestamp": "2025-01-17T20:30:00Z"
}
```

3. **Resposta:**
```json
{
  "type": "response",
  "data": {
    "answer": "O sistema de segurança está funcionando perfeitamente...",
    "confidence": 0.88,
    "sources": ["llm", "system_metrics"],
    "metadata": {
      "question_type": "system_status",
      "response_length": 156,
      "has_context": true
    },
    "timestamp": "2025-01-17T20:30:00Z"
  }
}
```

4. **Fine-tuning iniciado:**
```json
{
  "type": "fine_tuning_started",
  "message": "Iniciando fine-tuning...",
  "timestamp": "2025-01-17T20:30:00Z"
}
```

5. **Fine-tuning concluído:**
```json
{
  "type": "fine_tuning_completed",
  "data": {
    "success": true,
    "improvements": {
      "abiss_threshold": 0.02,
      "nnis_sensitivity": 0.03
    },
    "new_thresholds": {
      "abiss_threat_threshold": 0.93,
      "nnis_threat_threshold": 0.92
    },
    "training_loss": 0.15,
    "timestamp": "2025-01-17T20:30:00Z"
  }
}
```

## 💡 **Exemplos de Uso**

### **1. Consultas sobre Segurança**

#### **Ameaças Recentes**
```bash
curl -X POST "http://127.0.0.1:8000/api/llm/query" \
  -H "Content-Type: application/json" \
  -d '{
    "question": "Quais foram as últimas ameaças bloqueadas pelo sistema?",
    "include_system_context": true
  }'
```

#### **Análise de Vulnerabilidades**
```bash
curl -X POST "http://127.0.0.1:8000/api/llm/query" \
  -H "Content-Type: application/json" \
  -d '{
    "question": "Existem vulnerabilidades críticas no sistema?",
    "context": {
      "include_security_data": true,
      "include_performance_metrics": true
    }
  }'
```

### **2. Consultas sobre Usuários**

#### **Estatísticas de Usuários**
```bash
curl -X POST "http://127.0.0.1:8000/api/llm/query" \
  -H "Content-Type: application/json" \
  -d '{
    "question": "Quantos usuários foram cadastrados recentemente?",
    "include_system_context": true
  }'
```

#### **Análise de Atividade**
```bash
curl -X POST "http://127.0.0.1:8000/api/llm/query" \
  -H "Content-Type: application/json" \
  -d '{
    "question": "Qual é o padrão de atividade dos usuários?",
    "context": {
      "include_user_stats": true,
      "include_performance_metrics": true
    }
  }'
```

### **3. Consultas sobre Performance**

#### **Status do Sistema**
```bash
curl -X POST "http://127.0.0.1:8000/api/llm/query" \
  -H "Content-Type: application/json" \
  -d '{
    "question": "Como está a performance do sistema hoje?",
    "include_system_context": true
  }'
```

#### **Otimizações Recomendadas**
```bash
curl -X POST "http://127.0.0.1:8000/api/llm/query" \
  -H "Content-Type: application/json" \
  -d '{
    "question": "Que otimizações você recomenda para o sistema?",
    "context": {
      "include_performance_metrics": true,
      "include_security_data": true
    }
  }'
```

## 🔧 **Configuração e Personalização**

### **Variáveis de Ambiente**

```bash
# Configurações do modelo
GEMMA_MODEL_PATH=models/gemma-3n/extracted
GEMMA_MAX_LENGTH=2048
GEMMA_TEMPERATURE=0.7
GEMMA_TOP_P=0.9

# Configurações de fine-tuning
LLM_AUTO_FINE_TUNING=true
LLM_FINE_TUNING_INTERVAL=24
LLM_MIN_IMPROVEMENT_THRESHOLD=0.01

# Configurações de cache
LLM_CACHE_ENABLED=true
LLM_CACHE_TTL=3600
LLM_CACHE_MAX_SIZE=1000
```

### **Arquivo de Configuração YAML**

```yaml
llm:
  model:
    path: "models/gemma-3n/extracted"
    max_length: 2048
    temperature: 0.7
    top_p: 0.9
  
  fine_tuning:
    auto_enabled: true
    interval_hours: 24
    min_improvement: 0.01
    max_training_time: 30
  
  cache:
    enabled: true
    ttl_seconds: 3600
    max_size: 1000
    eviction_policy: "lru"
  
  context:
    max_length: 2000
    include_system_info: true
    include_security_data: true
    include_user_stats: true
```

## 📊 **Métricas e Monitoramento**

### **Métricas do Serviço**

- **Total de consultas**: Número total de perguntas processadas
- **Taxa de sucesso**: Porcentagem de respostas bem-sucedidas
- **Tempo médio de resposta**: Performance do modelo
- **Tamanho do cache**: Eficiência do sistema de cache
- **Status de carregamento**: Estado do modelo
- **Status de treinamento**: Estado do fine-tuning

### **Monitoramento em Tempo Real**

```bash
# Status do serviço
curl "http://127.0.0.1:8000/api/llm/status"

# Contexto do sistema
curl "http://127.0.0.1:8000/api/llm/context"

# Health check
curl "http://127.0.0.1:8000/health/detailed"
```

## 🚨 **Solução de Problemas**

### **Problemas Comuns**

#### **1. Modelo não carregado**
```bash
# Verificar status
curl "http://127.0.0.1:8000/api/llm/status"

# Carregar manualmente
curl -X POST "http://127.0.0.1:8000/api/llm/load-model"
```

#### **2. Respostas lentas**
```bash
# Verificar métricas
curl "http://127.0.0.1:8000/api/llm/status"

# Verificar contexto do sistema
curl "http://127.0.0.1:8000/api/llm/context"
```

#### **3. Fine-tuning falhando**
```bash
# Verificar logs
tail -f logs/llm_service.log

# Forçar fine-tuning
curl -X POST "http://127.0.0.1:8000/api/llm/fine-tuning" \
  -H "Content-Type: application/json" \
  -d '{"force": true}'
```

### **Logs e Debugging**

```bash
# Logs do serviço LLM
tail -f logs/llm_service.log

# Logs do sistema
tail -f logs/atous_sec_network.log

# Logs de erro
grep "ERROR" logs/llm_service.log
```

## 🔒 **Segurança e Privacidade**

### **Proteções Implementadas**

- **Validação de entrada**: Todas as perguntas são validadas
- **Sanitização de contexto**: Dados sensíveis são filtrados
- **Rate limiting**: Proteção contra abuso
- **Logs de auditoria**: Rastreamento de todas as consultas
- **Isolamento de contexto**: Separação entre usuários

### **Configurações de Segurança**

```yaml
security:
  input_validation: true
  context_sanitization: true
  rate_limiting: true
  audit_logging: true
  max_question_length: 1000
  max_context_size: 5000
```

## 📚 **Recursos Adicionais**

### **Documentação Relacionada**

- [WEBSOCKET_GUIDE.md](./WEBSOCKET_GUIDE.md) - Guia de WebSockets
- [WEBSOCKET_API.md](./WEBSOCKET_API.md) - API de WebSockets
- [collection.json](./collection.json) - Collection Postman completa

### **Exemplos de Cliente**

#### **JavaScript (Browser)**
```javascript
// Conectar ao WebSocket LLM
const ws = new WebSocket('ws://127.0.0.1:8000/api/llm/ws');

ws.onmessage = (event) => {
  const message = JSON.parse(event.data);
  console.log('Resposta:', message);
};

// Fazer pergunta
ws.send(JSON.stringify({
  type: 'query',
  question: 'Como está o sistema de segurança?'
}));
```

#### **Python**
```python
import requests
import json

# Consulta REST
response = requests.post(
    'http://127.0.0.1:8000/api/llm/query',
    json={
        'question': 'Quais foram as últimas ameaças?',
        'include_system_context': True
    }
)

print(json.dumps(response.json(), indent=2))
```

#### **cURL**
```bash
# Consulta simples
curl -X POST "http://127.0.0.1:8000/api/llm/query" \
  -H "Content-Type: application/json" \
  -d '{"question": "Status do sistema?"}'

# Com contexto
curl -X POST "http://127.0.0.1:8000/api/llm/query" \
  -H "Content-Type: application/json" \
  -d '{
    "question": "Análise de segurança",
    "context": {"include_security_data": true}
  }'
```

## 🎯 **Próximos Passos**

### **Melhorias Planejadas**

1. **Modelos especializados** para diferentes domínios
2. **Fine-tuning adaptativo** baseado em feedback
3. **Integração com mais fontes** de dados
4. **Interface web** para consultas interativas
5. **Análise preditiva** de ameaças

### **Roadmap de Desenvolvimento**

- **Fase 1**: Sistema básico funcionando ✅
- **Fase 2**: Fine-tuning automático ✅
- **Fase 3**: Interface web interativa 🔄
- **Fase 4**: Modelos especializados 📋
- **Fase 5**: Análise preditiva 📋

---

**🎊 O sistema LLM da ATous Secure Network está pronto para uso! 🎊**

**Status**: ✅ **FUNCIONAL E TESTADO**
**Modelo**: Gemma 3N integrado
**Capacidades**: Consultas, fine-tuning, assistência
**Integração**: 100% com sistema de segurança
