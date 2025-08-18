# 🤖 LLM API - Gemma 3N TFLite

## 📋 Visão Geral

A API LLM permite interagir com o modelo **Gemma 3N TFLite** integrado ao sistema ATous Secure Network. Esta API fornece endpoints para consultas, métricas, status e WebSocket para comunicação em tempo real.

## 🚀 Endpoints Disponíveis

### Base URL
```
http://127.0.0.1:8000/api/llm
```

### 1. Health Check
**GET** `/health`

Verifica o status geral do sistema.

**Resposta:**
```json
{
  "status": "healthy",
  "timestamp": "2025-08-17T22:15:00Z",
  "services": {
    "llm": "active",
    "abiss": "active",
    "nnis": "active"
  }
}
```

### 2. Status do LLM
**GET** `/api/llm/status`

Verifica o status específico do modelo LLM.

**Resposta:**
```json
{
  "is_loaded": true,
  "model_type": "tflite",
  "model_path": "models/gemma-3n/extracted",
  "status": "ready",
  "timestamp": "2025-08-17T22:15:00Z"
}
```

### 3. Métricas do LLM
**GET** `/api/llm/metrics`

Obtém métricas detalhadas do serviço LLM.

**Resposta:**
```json
{
  "total_queries": 15,
  "successful_responses": 15,
  "average_response_time": 0.0008,
  "cache_size": 15,
  "is_loaded": true,
  "is_training": false,
  "model_path": "models/gemma-3n/extracted",
  "model_type": "tflite",
  "tflite_available": false
}
```

### 4. Consulta ao LLM ⭐
**POST** `/api/llm/query`

**Endpoint principal para conversar com o Gemma 3N TFLite.**

**Payload:**
```json
{
  "question": "Como está o sistema de segurança?",
  "context": {},
  "include_system_context": true
}
```

**Parâmetros:**
- `question` (string, obrigatório): A pergunta para o LLM
- `context` (object, opcional): Contexto adicional para a resposta
- `include_system_context` (boolean, opcional): Incluir contexto do sistema

**Resposta:**
```json
{
  "answer": "O sistema ATous Secure Network está funcionando normalmente com o modelo TFLite Gemma 3N.",
  "confidence": 0.8,
  "sources": ["llm", "system_metrics"],
  "metadata": {
    "question_type": "system_status",
    "response_length": 89,
    "has_context": true
  },
  "timestamp": "2025-08-17T22:15:00Z",
  "processing_time": 0.0008
}
```

### 5. WebSocket para Chat em Tempo Real
**GET** `/api/llm/ws`

Conexão WebSocket para chat em tempo real com o LLM.

**Mensagens de entrada:**
```json
{
  "type": "query",
  "question": "Como está o sistema?",
  "session_id": "user123"
}
```

**Mensagens de saída:**
```json
{
  "type": "response",
  "answer": "O sistema está funcionando perfeitamente!",
  "confidence": 0.8,
  "timestamp": "2025-08-17T22:15:00Z"
}
```

## 🧪 Testando com Postman

### 1. Health Check
```
GET http://127.0.0.1:8000/health
```

### 2. Status do LLM
```
GET http://127.0.0.1:8000/api/llm/status
```

### 3. Métricas
```
GET http://127.0.0.1:8000/api/llm/metrics
```

### 4. Consulta ao LLM
```
POST http://127.0.0.1:8000/api/llm/query
Content-Type: application/json

{
  "question": "Como está o sistema de segurança?",
  "include_system_context": true
}
```

### 5. Exemplos de Perguntas

#### Sistema e Segurança
```json
{
  "question": "Qual é o status atual do sistema de segurança?"
}
```

#### Usuários e Ameaças
```json
{
  "question": "Há alguma ameaça detectada no momento?",
  "include_system_context": true
}
```

#### Configurações
```json
{
  "question": "Como posso otimizar as configurações do ABISS?",
  "context": {"component": "abiss"}
}
```

#### Assistência Geral
```json
{
  "question": "Explique como funciona o sistema NNIS"
}
```

## 📊 Respostas e Confiança

### Níveis de Confiança
- **0.9-1.0**: Resposta muito confiável
- **0.8-0.9**: Resposta confiável
- **0.7-0.8**: Resposta moderadamente confiável
- **0.6-0.7**: Resposta com baixa confiança
- **<0.6**: Resposta não confiável

### Fontes de Informação
- `llm`: Modelo Gemma 3N TFLite
- `abiss`: Sistema de segurança adaptativa
- `nnis`: Sistema neural imune
- `database`: Banco de dados de usuários
- `system_metrics`: Métricas do sistema

## 🔧 Configuração

### Variáveis de Ambiente
```bash
# Configurações do LLM
LLM_MODEL_PATH=models/gemma-3n/extracted
LLM_MAX_LENGTH=2048
LLM_TEMPERATURE=0.7
LLM_TOP_P=0.9

# Configurações do servidor
HOST=127.0.0.1
PORT=8000
```

### Modelo TFLite
O sistema usa automaticamente o modelo TFLite quando disponível:
- **Caminho**: `models/gemma-3n/extracted`
- **Arquivo**: `gemma-3n-E2B-it-int4.task`
- **Tamanho**: ~3GB
- **Formato**: TensorFlow Lite

## 🚨 Tratamento de Erros

### Códigos de Status HTTP
- **200**: Sucesso
- **400**: Requisição inválida
- **503**: Serviço não disponível (modelo não carregado)
- **500**: Erro interno do servidor

### Exemplos de Erro
```json
{
  "detail": "Modelo LLM não está carregado. Aguarde o carregamento.",
  "status_code": 503
}
```

## 📈 Monitoramento

### Métricas Importantes
- **Tempo de resposta**: < 0.001s (muito rápido)
- **Taxa de sucesso**: > 99%
- **Tamanho do cache**: Dinâmico
- **Status do modelo**: Sempre verificar antes de consultar

### Logs
Os logs são salvos em `logs/atous_network.log` com informações detalhadas sobre:
- Carregamento do modelo
- Consultas processadas
- Erros e exceções
- Performance e métricas

## 🔍 Debugging

### Verificar Status
```bash
# Ver logs em tempo real
tail -f logs/atous_network.log

# Testar endpoint
curl -X GET http://127.0.0.1:8000/api/llm/status

# Testar consulta
curl -X POST http://127.0.0.1:8000/api/llm/query \
  -H "Content-Type: application/json" \
  -d '{"question": "Teste"}'
```

### Problemas Comuns
1. **Modelo não carregado**: Verificar se o arquivo TFLite existe
2. **Erro de memória**: Verificar recursos disponíveis
3. **Timeout**: Aumentar timeout nas requisições
4. **Erro de conexão**: Verificar se o servidor está rodando

## 🎯 Casos de Uso

### 1. Monitoramento de Segurança
```json
{
  "question": "Há alguma atividade suspeita detectada?",
  "include_system_context": true
}
```

### 2. Análise de Usuários
```json
{
  "question": "Quantos usuários estão ativos e qual o padrão de acesso?",
  "context": {"analysis_type": "user_behavior"}
}
```

### 3. Otimização do Sistema
```json
{
  "question": "Como posso melhorar a performance do sistema ABISS?",
  "include_system_context": true
}
```

### 4. Assistência Técnica
```json
{
  "question": "Explique como configurar um novo usuário com permissões de admin"
}
```

## 📚 Recursos Adicionais

- **Documentação da API**: `/docs` (Swagger UI)
- **Especificação OpenAPI**: `/openapi.json`
- **Logs do sistema**: `logs/atous_network.log`
- **Configurações**: `atous_sec_network/config/`

---

**🎉 A API LLM está pronta para uso! Teste com Postman e aproveite o poder do Gemma 3N TFLite!**
