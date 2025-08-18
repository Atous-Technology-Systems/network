# 🚀 Quick Start - LLM API Gemma 3N TFLite

## ⚡ Início Rápido

Este guia permite testar a API LLM em **menos de 5 minutos**!

## 📋 Pré-requisitos

- ✅ Sistema ATous rodando na porta 8000
- ✅ Modelo Gemma 3N TFLite carregado
- ✅ Postman ou similar instalado

## 🔧 Passo 1: Verificar Status

### Health Check
```bash
GET http://127.0.0.1:8000/health
```

**Resposta esperada:**
```json
{
  "status": "healthy",
  "timestamp": "2025-08-17T22:15:00Z"
}
```

### Status do LLM
```bash
GET http://127.0.0.1:8000/api/llm/status
```

**Resposta esperada:**
```json
{
  "is_loaded": true,
  "model_type": "tflite",
  "model_path": "models/gemma-3n/extracted",
  "status": "ready"
}
```

## 🤖 Passo 2: Primeira Consulta

### Consulta Simples
```bash
POST http://127.0.0.1:8000/api/llm/query
Content-Type: application/json

{
  "question": "Como está o sistema de segurança?",
  "include_system_context": true
}
```

**Resposta esperada:**
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

## 📊 Passo 3: Verificar Métricas

### Métricas do LLM
```bash
GET http://127.0.0.1:8000/api/llm/metrics
```

**Resposta esperada:**
```json
{
  "total_queries": 1,
  "successful_responses": 1,
  "average_response_time": 0.0008,
  "cache_size": 1,
  "is_loaded": true,
  "model_type": "tflite"
}
```

## 🎯 Passo 4: Testar Diferentes Tipos de Perguntas

### 1. Sistema e Segurança
```json
{
  "question": "Qual é o status atual do sistema de segurança?"
}
```

### 2. Detecção de Ameaças
```json
{
  "question": "Há alguma ameaça detectada no momento?",
  "include_system_context": true
}
```

### 3. Usuários e Acesso
```json
{
  "question": "Quantos usuários estão ativos?",
  "include_system_context": true
}
```

### 4. Componentes Específicos
```json
{
  "question": "Como funciona o sistema ABISS?",
  "context": {"component": "abiss"}
}
```

## 🔍 Passo 5: Debugging

### Se algo não funcionar:

1. **Verificar logs:**
   ```bash
   tail -f logs/atous_network.log
   ```

2. **Verificar se o modelo está carregado:**
   ```bash
   GET http://127.0.0.1:8000/api/llm/status
   ```

3. **Verificar se o servidor está rodando:**
   ```bash
   GET http://127.0.0.1:8000/health
   ```

4. **Verificar arquivo do modelo:**
   ```bash
   ls -la models/gemma-3n/extracted/
   ```

## 📱 Usando Postman

### Importar Coleção
1. Abra o Postman
2. Clique em "Import"
3. Selecione o arquivo: `docs/api/ATous_LLM_API.postman_collection.json`
4. A coleção será importada com todos os endpoints pré-configurados

### Testar Endpoints
1. **Health Check** - Verificar se o sistema está rodando
2. **LLM Status** - Verificar se o modelo está carregado
3. **LLM Query** - Fazer perguntas ao Gemma 3N TFLite
4. **LLM Metrics** - Ver métricas de performance

## 🚨 Problemas Comuns

### 1. "Connection refused"
- **Solução**: Verificar se o servidor está rodando na porta 8000

### 2. "Modelo LLM não está carregado"
- **Solução**: Aguardar o carregamento ou verificar se o arquivo TFLite existe

### 3. "Timeout"
- **Solução**: Aumentar timeout para 10-30 segundos

### 4. "500 Internal Server Error"
- **Solução**: Verificar logs para detalhes do erro

## 🎉 Sucesso!

Se você conseguiu:
- ✅ Fazer health check
- ✅ Ver status do LLM
- ✅ Fazer consultas
- ✅ Ver métricas

**Parabéns! A API LLM está funcionando perfeitamente! 🎯**

## 📚 Próximos Passos

- **Documentação Completa**: [LLM_API.md](LLM_API.md)
- **Swagger UI**: `http://127.0.0.1:8000/docs`
- **WebSocket**: Testar chat em tempo real
- **Casos de Uso**: Explorar diferentes tipos de perguntas

---

**🤖 Agora você pode conversar com o Gemma 3N TFLite via API!**
