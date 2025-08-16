# 📚 Collection do Postman - ATous Secure Network

## 🚀 Visão Geral

Esta collection do Postman contém todos os endpoints implementados no sistema ATous Secure Network, organizados de forma lógica e com testes automatizados para facilitar o desenvolvimento e teste da API.

## 📋 Pré-requisitos

- **Postman**: Versão 8.0 ou superior
- **Servidor ATous**: Rodando em `http://127.0.0.1:8000`
- **Variáveis configuradas**: Conforme descrito abaixo

## 🔧 Configuração Inicial

### 1. Importar a Collection

1. Abra o Postman
2. Clique em "Import" (botão azul no canto superior esquerdo)
3. Arraste o arquivo `collection.json` ou clique em "Upload Files"
4. Selecione o arquivo e clique em "Import"

### 2. Configurar Variáveis

A collection usa as seguintes variáveis que devem ser configuradas:

| Variável | Valor Padrão | Descrição |
|----------|---------------|-----------|
| `base_url` | `http://127.0.0.1:8000` | URL base do servidor |
| `admin_api_key` | `dev-admin` | Chave de API para endpoints admin |
| `jwt_token` | `your-jwt-token-here` | Token JWT (quando implementado) |
| `timestamp` | `{{$timestamp}}` | Timestamp dinâmico |

**Para configurar as variáveis:**

1. Clique no ícone de engrenagem (⚙️) ao lado do nome da collection
2. Vá para a aba "Variables"
3. Configure os valores conforme necessário
4. Clique em "Save"

## 📊 Estrutura da Collection

### 🏠 Sistema Principal
- **Root**: Informações básicas da API
- **Documentação**: Swagger, ReDoc, OpenAPI Schema

### 🏥 Health Check
- **Health Principal**: Status geral dos sistemas
- **Health Detalhado**: Informações detalhadas
- **Ping**: Teste simples de conectividade

### 🔐 Admin (MVP)
- **Visão Geral**: Status administrativo do sistema
- **Status dos Sistemas**: Status detalhado de todos os componentes
- **Configurações**: Configurações atuais do sistema
- **Logs**: Logs recentes para monitoramento

### 🌐 Discovery
- **Listar Nós**: Lista todos os nós conhecidos na rede P2P
- **Registrar Nó**: Registra um novo nó na rede
- **Buscar por Capacidade**: Busca nós com capacidades específicas

### 📡 Relay
- **Status**: Status do sistema de retransmissão
- **Enviar Mensagem**: Envia mensagens através do relay
- **Mensagens Pendentes**: Lista mensagens pendentes

### 🤖 Agents
- **Listar Agentes**: Lista todos os agentes ativos
- **Status do Agente**: Status detalhado de um agente específico
- **Executar Comando**: Executa comandos em agentes

### 📋 Policies
- **Listar Políticas**: Lista políticas de segurança ativas
- **Criar Política**: Cria nova política de segurança
- **Aplicar Política**: Aplica política ao sistema

### 🔒 Presets de Segurança
- **Listar Presets**: Lista presets disponíveis (dev, staging, production, security_test)
- **Aplicar Preset**: Aplica preset específico ao sistema
- **Configuração Atual**: Mostra configuração atualmente ativa

### 🔐 Criptografia
- **Criptografar via /api/crypto/encrypt**: Endpoint principal de criptografia
- **Criptografar via /api/security/encrypt**: Criptografia focada em segurança
- **Criptografar via /encrypt**: Interface simplificada

### 🌐 WebSocket Endpoints
- **/ws**: WebSocket principal para comunicação em tempo real
- **/api/ws**: WebSocket da API para comunicação estruturada
- **/websocket**: WebSocket genérico para compatibilidade

### 🧪 Testes de Carga e Performance
- **Rate Limiting**: Testa proteção contra spam
- **Payload Grande**: Testa limites de tamanho e proteção DDoS

### 🔧 Utilitários e Debug
- **Tempo de Resposta**: Verifica métricas de performance
- **Headers Customizados**: Testa processamento de headers

## 🎯 Ordem Recomendada de Testes

### 1. Teste de Conectividade
Execute primeiro o endpoint **"🔧 Teste de Conectividade"** em `📖 Documentação e Instruções` para verificar se o servidor está respondendo.

### 2. Verificação Básica
- **Root**: `/` - Informações básicas da API
- **Health Check**: `/health` - Status dos sistemas
- **API Info**: `/api/info` - Recursos disponíveis

### 3. Funcionalidades Admin
- **Admin Overview**: `/v1/admin/overview` - Visão geral administrativa
- **Status dos Sistemas**: `/v1/admin/systems` - Status detalhado

### 4. Funcionalidades Específicas
Teste as funcionalidades conforme sua necessidade:
- **Discovery**: Para redes P2P
- **Relay**: Para comunicação entre nós
- **Agents**: Para gerenciamento de agentes
- **Policies**: Para políticas de segurança
- **Presets**: Para configurações de segurança

### 5. Testes de Segurança
- **Criptografia**: Teste os endpoints de criptografia
- **Rate Limiting**: Execute múltiplas requisições rapidamente
- **WebSocket**: Teste comunicação em tempo real

## 🛡️ Recursos de Segurança

### Rate Limiting
O sistema implementa rate limiting para proteger contra spam e ataques DDoS. Execute múltiplas requisições rapidamente para testar:

```bash
# Execute o endpoint de teste múltiplas vezes
curl -X POST http://127.0.0.1:8000/api/v1/security/middleware/test \
  -H "Content-Type: application/json" \
  -d '{"test": "rate_limit"}'
```

### Presets de Segurança
O sistema suporta diferentes níveis de segurança:

- **dev/development**: Permissivo para desenvolvimento
- **staging**: Balanceado para pré-produção
- **production**: Máxima segurança
- **security_test**: Agressivo para testes de penetração

### Autenticação Admin
Endpoints administrativos requerem o header `X-Admin-Api-Key`:

```bash
curl -H "X-Admin-Api-Key: dev-admin" \
  http://127.0.0.1:8000/v1/admin/overview
```

## 📝 Logs e Debug

### Console do Postman
Todos os requests incluem logs automáticos no console do Postman:

1. Abra o Postman
2. Clique em "Console" (ícone de terminal no canto inferior esquerdo)
3. Execute qualquer request da collection
4. Veja os logs detalhados no console

### Testes Automatizados
Cada request inclui testes automáticos que verificam:

- ✅ Status code não é 500 (erro interno)
- ⚡ Tempo de resposta menor que 5 segundos
- 📄 Content-Type válido
- 🔍 Estrutura JSON válida (quando aplicável)
- 🛡️ Respostas adequadas para endpoints de segurança

### Métricas Coletadas
A collection coleta automaticamente métricas de performance:

- URL do request
- Método HTTP
- Status code
- Tempo de resposta
- Timestamp

## 🔍 Troubleshooting

### Problemas Comuns

#### 1. Servidor não responde
```
❌ Error: connect ECONNREFUSED 127.0.0.1:8000
```
**Solução**: Verifique se o servidor está rodando:
```bash
# No diretório do projeto
./venv/Scripts/python.exe -m uvicorn atous_sec_network.api.server:app --host 127.0.0.1 --port 8000
```

#### 2. Erro 401 Unauthorized
```
❌ 401 Unauthorized
```
**Solução**: Verifique se a chave admin está configurada corretamente:
- Confirme que `admin_api_key` está definida como `dev-admin`
- Verifique se o header `X-Admin-Api-Key` está sendo enviado

#### 3. Erro 429 Too Many Requests
```
❌ 429 Too Many Requests
```
**Solução**: Este é o comportamento esperado do rate limiting. Aguarde alguns segundos e tente novamente.

#### 4. Erro 403 Forbidden
```
❌ 403 Forbidden
```
**Solução**: A requisição foi bloqueada pelo sistema de segurança. Verifique:
- Se não está enviando payloads suspeitos
- Se não está excedendo limites de tamanho
- Se não está usando padrões maliciosos

### Verificação de Status

Para verificar o status geral do sistema:

```bash
# Health check básico
curl http://127.0.0.1:8000/health

# Health check detalhado
curl http://127.0.0.1:8000/health/detailed

# Informações da API
curl http://127.0.0.1:8000/api/info
```

## 📚 Recursos Adicionais

### Documentação da API
- **Swagger UI**: `http://127.0.0.1:8000/docs`
- **ReDoc**: `http://127.0.0.1:8000/redoc`
- **OpenAPI Schema**: `http://127.0.0.1:8000/openapi.json`

### Scripts de Teste
O projeto inclui scripts de teste automatizados:

```bash
# Health check para CI/CD
python scripts/ci_health_check.py

# Aplicar presets de segurança
python scripts/apply_security_preset.py production
```

### Configurações de Segurança
Arquivos de configuração disponíveis:

- `config/security_presets.yaml`: Configurações dos presets
- `docs/security/README.md`: Documentação de segurança
- `docs/technical/ENDPOINTS_MAP.md`: Mapa completo de endpoints

## 🤝 Contribuição

Para contribuir com a collection:

1. **Teste novos endpoints**: Adicione novos endpoints conforme implementados
2. **Melhore testes**: Adicione testes específicos para funcionalidades
3. **Documentação**: Mantenha as descrições atualizadas
4. **Exemplos**: Adicione exemplos de payloads e respostas

## 📞 Suporte

Se encontrar problemas:

1. Verifique os logs no console do Postman
2. Execute o health check para verificar status do sistema
3. Consulte a documentação técnica em `docs/`
4. Use os scripts de teste para diagnóstico

---

**Versão da Collection**: 4.0.0  
**Última Atualização**: Janeiro 2025  
**Compatibilidade**: Postman 8.0+  
**Sistema**: ATous Secure Network 2.0.0
