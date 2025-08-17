# Guia da Collection do Postman - ATous Secure Network

Este documento fornece instrucoes detalhadas para usar a collection do Postman do sistema ATous Secure Network.

## Pre-requisitos

- **Postman**: Versao 8.0 ou superior
- **Servidor**: ATous Secure Network rodando em http://127.0.0.1:8000
- **Conhecimento**: Basico de APIs REST e autenticacao

## Configuracao Inicial

### 1. Importar Collection

1. Abra o Postman
2. Clique em "Import"
3. Selecione o arquivo `docs/collection.json`
4. A collection sera importada com todas as pastas e endpoints

### 2. Configurar Variaveis

1. Clique no icone de engrenagem ao lado do nome da collection
2. Vá para a aba "Variables"
3. Configure as seguintes variaveis:

**Variaveis Globais:**
- `base_url`: http://127.0.0.1:8000
- `admin_api_key`: dev-admin
- `jwt_token`: (sera preenchido apos login)
- `refresh_token`: (sera preenchido apos login)
- `timestamp`: {{$timestamp}}

### 3. Verificar Conectividade

Execute primeiro o endpoint "Teste de Conectividade" para verificar se o servidor esta respondendo.

## Estrutura da Collection

### Sistema Principal
- Root - Informacoes da API
- Documentacao Swagger
- Documentacao ReDoc
- OpenAPI Schema

### Health Check
- Status Geral do Sistema
- Status Detalhado dos Componentes

### Autenticacao e Usuarios
- Registrar Usuario
- Login de Usuario
- Refresh Token
- Perfil do Usuario
- Atualizar Perfil
- Alterar Senha
- Sessoes Ativas
- Logout
- Listar Usuarios (Admin)
- Estatisticas de Seguranca
- Logs de Acesso
- Estatisticas de Tokens
- Limpeza de Manutencao (Admin)

### Admin (MVP)
- Visao Geral do Sistema
- Eventos do Sistema

### Discovery
- Buscar Servicos por Nome

### Relay
- Status do Relay
- Enviar Mensagem via Relay
- Configurar Relay

### Agents
- Listar Agentes
- Status do Agente
- Comando para Agente

### Policies
- Listar Politicas
- Criar Nova Politica

### Seguranca Avancada
- Status ABISS
- Status NNIS
- Configurar Preset de Seguranca

### Criptografia
- Criptografar Dados (endpoints disponíveis: `/api/crypto/encrypt`, `/api/security/encrypt`, `/encrypt`)
- **Nota**: Endpoints de descriptografia não estão implementados na versão atual
- **Nota**: Geração de chaves é feita internamente pelo sistema

### WebSocket Endpoints
- **WebSocket Principal** (`/ws`) - Conexão principal para comunicação em tempo real
- **WebSocket API** (`/api/ws`) - Endpoint específico da API
- **WebSocket Genérico** (`/websocket`) - Para testes e desenvolvimento
- **WebSocket Test Node** (`/ws/test_node`) - Para teste de conectividade de nós
- **Nota**: Use ferramentas como wscat ou Postman para testar conexões WebSocket

### Testes de Carga e Performance
- Teste de Conectividade Multipla
- Teste de Rate Limiting

### Utilitarios e Debug
- Logs do Sistema
- Status de Memoria

## Ordem Recomendada de Testes

Execute primeiro o endpoint **"Teste de Conectividade"** em `Documentacao e Instrucoes` para verificar se o servidor esta respondendo.

### Sequencia de Testes

1. **Conectividade Basica**
   - Teste de Conectividade
   - Health Check

2. **Autenticacao**
   - Registrar Usuario
   - Login de Usuario
   - Verificar JWT Token

3. **Funcionalidades Basicas**
   - Perfil do Usuario
   - Refresh Token
   - Logout

4. **Funcionalidades Avancadas**
   - Admin Overview
   - Discovery
   - Criptografia

5. **Testes de Seguranca**
   - Rate Limiting
   - Validacao de Entrada
   - Protecao contra Ataques

## Recursos de Seguranca

### Autenticacao
- **JWT Tokens**: Access tokens com validade de 1 hora
- **Refresh Tokens**: Renovacao automatica de tokens
- **Rate Limiting**: Protecao contra ataques de forca bruta

### Controle de Acesso
- **RBAC**: Controle de acesso baseado em roles
- **Permissoes Granulares**: Controle fino de acesso
- **Auditoria**: Logs de todas as acoes

### Protecao de Sistema
- **Input Validation**: Validacao rigorosa de entrada
- **DDoS Protection**: Protecao contra ataques distribuidos
- **Security Headers**: Headers de seguranca automaticos

### Presets de Seguranca
- **Development**: Configuracao para desenvolvimento
- **Production**: Configuracao para producao
- **High Security**: Configuracao de alta seguranca

## Logs e Debug

### Console do Postman
Todos os requests incluem logs automaticos no console do Postman:

- **Pre-request Scripts**: Logs antes de cada request
- **Test Scripts**: Logs apos cada response
- **Variaveis**: Logs de variaveis de ambiente
- **Headers**: Logs de headers importantes

### Metricas Coletadas
- Tempo de resposta
- Tamanho da resposta
- Status codes
- Headers de resposta
- Timestamps

### Testes Automatizados
- Status code nao e 500 (erro interno)
- Tempo de resposta menor que 5 segundos
- Content-Type valido
- Estrutura JSON valida (quando aplicavel)
- Respostas adequadas para endpoints de seguranca

## Troubleshooting

### Problemas Comuns

#### 1. Servidor Nao Responde
- Verifique se o servidor esta rodando
- Confirme a URL base nas variaveis
- Verifique firewall/proxy

#### 2. Erro de Autenticacao
- Verifique se o JWT token esta configurado
- Confirme se o token nao expirou
- Use o refresh token para renovar

#### 3. Rate Limiting
- Aguarde o tempo de bloqueio
- Reduza a frequencia de requests
- Verifique os limites configurados

#### 4. Erro de Permissao
- Verifique se o usuario tem as permissoes necessarias
- Confirme se o role esta configurado corretamente
- Use um usuario com permissoes adequadas

### Logs de Erro

#### Console do Postman
- Verifique o console para logs detalhados
- Procure por mensagens de erro especificas
- Verifique os timestamps dos erros

#### Headers de Resposta
- `X-RateLimit-Remaining`: Requests restantes
- `X-RateLimit-Reset`: Tempo para reset do limite
- `X-Request-ID`: ID unico para rastreamento

## Exemplos de Uso

### Fluxo de Autenticacao

1. **Registrar Usuario**
   ```bash
   POST {{base_url}}/auth/register
   ```

2. **Fazer Login**
   ```bash
   POST {{base_url}}/auth/login
   ```

3. **Usar Token**
   ```bash
   GET {{base_url}}/auth/profile
   Authorization: Bearer {{jwt_token}}
   ```

4. **Refresh Token**
   ```bash
   POST {{base_url}}/auth/refresh
   ```

### Testes de Seguranca

1. **Rate Limiting**
   - Execute multiplos requests rapidamente
   - Verifique se retorna 429 (Too Many Requests)

2. **Validacao de Entrada**
   - Envie dados invalidos
   - Verifique se retorna 400 (Bad Request)

3. **Autenticacao**
   - Envie requests sem token
   - Verifique se retorna 401 (Unauthorized)

## Manutencao

### Atualizacoes da Collection

- A collection e atualizada regularmente
- Novos endpoints sao adicionados conforme implementados
- Testes sao atualizados para novas funcionalidades

### Backup

- Faca backup da collection antes de atualizacoes
- Exporte a collection para arquivo JSON
- Mantenha versoes anteriores se necessario

### Suporte

- Para problemas tecnicos, consulte a documentacao
- Para bugs na collection, abra uma issue
- Para sugestoes, envie um pull request

## Conclusao

Esta collection do Postman fornece uma ferramenta completa para testar e validar o sistema ATous Secure Network. Com testes automatizados, logs detalhados e exemplos praticos, ela facilita o desenvolvimento e teste da API.

Siga sempre a ordem recomendada de testes e verifique os logs para identificar problemas rapidamente. A collection e mantida atualizada com as ultimas funcionalidades implementadas.
