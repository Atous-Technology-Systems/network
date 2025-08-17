# 🔌 API de WebSockets - ATous Secure Network

## 📋 Visão Geral

A API de WebSockets da ATous Secure Network fornece endpoints REST para monitorar, configurar e gerenciar todos os WebSockets do sistema. Esta documentação cobre todos os endpoints disponíveis com exemplos completos.

## 🌐 Base URL

```
http://127.0.0.1:8000/api/websocket
```

## 🔑 Autenticação

Atualmente, os endpoints de WebSocket não requerem autenticação para facilitar o desenvolvimento e testes.

## 📊 Endpoints Disponíveis

### 1. **Status dos WebSockets**

**Endpoint**: `GET /api/websocket/status`

**Descrição**: Obter status atual de todos os WebSockets ativos.

**Funcionalidades**:
- ✅ Status operacional dos WebSockets
- 📊 Conexões ativas e mensagens processadas
- 🛡️ Métricas de segurança e performance
- 📈 Estatísticas de uso por endpoint

**Resposta**:
```json
{
  "websocket_status": "operational",
  "active_connections": 5,
  "total_messages": 1250,
  "endpoints": {
    "/ws": {
      "status": "active",
      "connections": 2,
      "messages": 450,
      "last_activity": "2025-08-17T22:53:08.000000+00:00"
    },
    "/api/ws": {
      "status": "active",
      "connections": 1,
      "messages": 300,
      "last_activity": "2025-08-17T22:53:08.000000+00:00"
    },
    "/websocket": {
      "status": "active",
      "connections": 1,
      "messages": 200,
      "last_activity": "2025-08-17T22:53:08.000000+00:00"
    },
    "/ws/test_node": {
      "status": "active",
      "connections": 1,
      "messages": 300,
      "last_activity": "2025-08-17T22:53:08.000000+00:00"
    }
  },
  "security": {
    "encrypted_connections": 3,
    "blocked_attempts": 0,
    "last_security_check": "2025-08-17T22:53:08.000000+00:00"
  },
  "performance": {
    "average_response_time": "0.002s",
    "peak_connections": 8,
    "total_data_transferred": "2.5MB"
  },
  "timestamp": "2025-08-17T22:53:08.000000+00:00"
}
```

**Exemplo de Uso**:
```bash
curl -X GET "http://127.0.0.1:8000/api/websocket/status" \
  -H "Accept: application/json"
```

**Códigos de Status**:
- `200 OK`: Status obtido com sucesso
- `500 Internal Server Error`: Erro interno do servidor

---

### 2. **Configuração dos WebSockets**

**Endpoint**: `GET /api/websocket/config`

**Descrição**: Obter configurações atuais dos WebSockets.

**Funcionalidades**:
- ⚙️ Configurações gerais (limites, timeouts)
- 🛡️ Configurações de segurança
- 🔌 Configurações por endpoint
- 📊 Parâmetros de performance

**Resposta**:
```json
{
  "websocket_config": {
    "max_connections": 100,
    "max_message_size": 1048576,
    "connection_timeout": 30,
    "keep_alive_interval": 25,
    "max_messages_per_connection": 10000
  },
  "security_config": {
    "encryption_enabled": true,
    "authentication_required": false,
    "allowed_origins": ["*"],
    "rate_limiting": {
      "enabled": true,
      "max_messages_per_minute": 1000
    }
  },
  "endpoints_config": {
    "/ws": {
      "enabled": true,
      "max_connections": 50,
      "features": ["json", "text", "echo"],
      "security_level": "standard"
    },
    "/api/ws": {
      "enabled": true,
      "max_connections": 25,
      "features": ["json", "text", "api_context"],
      "security_level": "enhanced"
    },
    "/websocket": {
      "enabled": true,
      "max_connections": 25,
      "features": ["json", "text", "generic"],
      "security_level": "basic"
    },
    "/ws/test_node": {
      "enabled": true,
      "max_connections": 10,
      "features": ["json", "text", "node_testing"],
      "security_level": "monitoring"
    }
  },
  "timestamp": "2025-08-17T22:53:08.000000+00:00"
}
```

**Exemplo de Uso**:
```bash
curl -X GET "http://127.0.0.1:8000/api/websocket/config" \
  -H "Accept: application/json"
```

**Códigos de Status**:
- `200 OK`: Configuração obtida com sucesso
- `500 Internal Server Error`: Erro interno do servidor

---

### 3. **Endpoints WebSocket Disponíveis**

**Endpoint**: `GET /api/websocket/endpoints`

**Descrição**: Lista todos os endpoints WebSocket disponíveis.

**Funcionalidades**:
- 🔌 Todos os endpoints WebSocket ativos
- 📋 Funcionalidades de cada endpoint
- 🛡️ Níveis de segurança
- 📊 Capacidades e limitações

**Resposta**:
```json
{
  "available_endpoints": [
    {
      "url": "/ws",
      "name": "WebSocket Principal",
      "description": "Endpoint principal para comunicação geral e testes",
      "features": ["json", "text", "echo"],
      "security_level": "standard",
      "max_connections": 50,
      "status": "active"
    },
    {
      "url": "/api/ws",
      "name": "WebSocket da API",
      "description": "Endpoint especializado para operações da API",
      "features": ["json", "text", "api_context"],
      "security_level": "enhanced",
      "max_connections": 25,
      "status": "active"
    },
    {
      "url": "/websocket",
      "name": "WebSocket Genérico",
      "description": "Endpoint genérico para operações básicas",
      "features": ["json", "text", "generic"],
      "security_level": "basic",
      "max_connections": 25,
      "status": "active"
    },
    {
      "url": "/ws/test_node",
      "name": "WebSocket de Teste de Nó",
      "description": "Endpoint para testes de conectividade de nós",
      "features": ["json", "text", "node_testing"],
      "security_level": "monitoring",
      "max_connections": 10,
      "status": "active"
    }
  ],
  "total_endpoints": 4,
  "timestamp": "2025-08-17T22:53:08.000000+00:00"
}
```

**Exemplo de Uso**:
```bash
curl -X GET "http://127.0.0.1:8000/api/websocket/endpoints" \
  -H "Accept: application/json"
```

**Códigos de Status**:
- `200 OK`: Endpoints listados com sucesso
- `500 Internal Server Error`: Erro interno do servidor

---

### 4. **Health Check dos WebSockets**

**Endpoint**: `GET /api/websocket/health`

**Descrição**: Verificação de saúde dos WebSockets.

**Funcionalidades**:
- 🟢 Status operacional geral
- 🔌 Conectividade dos endpoints
- 📊 Métricas básicas de saúde
- ⚠️ Problemas detectados

**Resposta**:
```json
{
  "status": "healthy",
  "websocket_health": {
    "overall_status": "healthy",
    "active_endpoints": 4,
    "total_connections": 5,
    "last_check": "2025-08-17T22:53:08.000000+00:00"
  },
  "endpoints_health": {
    "/ws": {
      "status": "active",
      "connections": 2,
      "last_activity": "2025-08-17T22:53:08.000000+00:00"
    },
    "/api/ws": {
      "status": "active",
      "connections": 1,
      "last_activity": "2025-08-17T22:53:08.000000+00:00"
    },
    "/websocket": {
      "status": "active",
      "connections": 1,
      "last_activity": "2025-08-17T22:53:08.000000+00:00"
    },
    "/ws/test_node": {
      "status": "active",
      "connections": 1,
      "last_activity": "2025-08-17T22:53:08.000000+00:00"
    }
  },
  "timestamp": "2025-08-17T22:53:08.000000+00:00"
}
```

**Exemplo de Uso**:
```bash
curl -X GET "http://127.0.0.1:8000/api/websocket/health" \
  -H "Accept: application/json"
```

**Códigos de Status**:
- `200 OK`: WebSockets saudáveis
- `503 Service Unavailable`: WebSockets com problemas
- `500 Internal Server Error`: Erro interno do servidor

## 🔌 Endpoints WebSocket

### **1. WebSocket Principal** - `/ws`

**URL**: `ws://127.0.0.1:8000/ws`

**Funcionalidades**:
- ✅ Conexão bidirecional estável
- 📨 Processamento de mensagens JSON e texto
- 🔄 Echo automático de mensagens
- 📊 Timestamps precisos
- 🛡️ Segurança integrada

**Mensagens Suportadas**:
- **JSON**: Objetos JavaScript com estrutura livre
- **Texto**: Strings simples para comunicação direta

**Exemplo de Conexão**:
```javascript
const ws = new WebSocket('ws://127.0.0.1:8000/ws');

ws.onopen = () => {
  console.log('WebSocket conectado!');
};

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Mensagem recebida:', data);
};

ws.onclose = () => {
  console.log('WebSocket desconectado');
};

ws.onerror = (error) => {
  console.error('Erro no WebSocket:', error);
};
```

**Respostas Esperadas**:
```json
// Mensagem de boas-vindas
{
  "status": "connected",
  "message": "WebSocket connection established",
  "endpoint": "/ws",
  "timestamp": "2025-08-17T22:53:08.000000+00:00"
}

// Echo de mensagem JSON
{
  "type": "response",
  "echo": {
    "action": "test",
    "message": "Hello WebSocket!",
    "timestamp": 1755471188.5604126
  },
  "timestamp": "2025-08-17T22:53:08.560412+00:00"
}

// Echo de mensagem de texto
{
  "type": "text_echo",
  "echo": "Mensagem de texto simples",
  "timestamp": "2025-08-17T22:53:08.166729+00:00"
}
```

---

### **2. WebSocket da API** - `/api/ws`

**URL**: `ws://127.0.0.1:8000/api/ws`

**Funcionalidades**:
- ✅ Funcionalidades específicas da API
- 📨 Processamento de mensagens JSON
- 🔄 Echo com contexto da API
- 📊 Timestamps e metadados
- 🛡️ Segurança e validação

**Exemplo de Uso**:
```javascript
const apiWs = new WebSocket('ws://127.0.0.1:8000/api/ws');

// Enviar operação da API
apiWs.send(JSON.stringify({
  api_action: 'get_status',
  endpoint: '/api/security/status',
  timestamp: Date.now()
}));

// Enviar comando de texto para API
apiWs.send('Status da API');
```

**Respostas Esperadas**:
```json
// Mensagem de boas-vindas da API
{
  "status": "connected",
  "message": "API WebSocket connection established",
  "endpoint": "/api/ws",
  "timestamp": "2025-08-17T22:53:08.564456+00:00"
}

// Echo da API
{
  "type": "api_response",
  "echo": {
    "api_action": "get_status",
    "endpoint": "/api/security/status",
    "timestamp": 1755471188.566047
  },
  "timestamp": "2025-08-17T22:53:08.566047+00:00"
}
```

---

### **3. WebSocket Genérico** - `/websocket`

**URL**: `ws://127.0.0.1:8000/websocket`

**Funcionalidades**:
- ✅ Funcionalidades básicas de WebSocket
- 📨 Processamento simples de mensagens
- 🔄 Echo genérico
- 📊 Timestamps básicos
- 🛡️ Segurança padrão

**Exemplo de Uso**:
```javascript
const genericWs = new WebSocket('ws://127.0.0.1:8000/websocket');

// Enviar mensagem genérica
genericWs.send(JSON.stringify({
  generic_action: 'ping',
  message: 'Teste de conectividade',
  timestamp: Date.now()
}));

// Enviar texto genérico
genericWs.send('Ping simples');
```

**Respostas Esperadas**:
```json
// Mensagem de boas-vindas genérica
{
  "status": "connected",
  "message": "Generic WebSocket connection established",
  "endpoint": "/websocket",
  "timestamp": "2025-08-17T22:53:08.569792+00:00"
}

// Echo genérico
{
  "type": "generic_response",
  "echo": {
    "generic_action": "ping",
    "message": "Teste de conectividade",
    "timestamp": 1755471188.5768237
  },
  "timestamp": "2025-08-17T22:53:08.577899+00:00"
}
```

---

### **4. WebSocket de Teste de Nó** - `/ws/test_node`

**URL**: `ws://127.0.0.1:8000/ws/test_node`

**Funcionalidades**:
- ✅ Testes de conectividade
- 📨 Validação de nós
- 🔄 Echo de teste
- 📊 Métricas de conectividade
- 🛡️ Segurança para nós

**Exemplo de Uso**:
```javascript
const nodeWs = new WebSocket('ws://127.0.0.1:8000/ws/test_node');

// Enviar teste de nó
nodeWs.send(JSON.stringify({
  test_action: 'node_test',
  node_id: 'test_node_001',
  node_type: 'security',
  timestamp: Date.now()
}));

// Enviar comando de teste
nodeWs.send('Teste de conectividade do nó');
```

**Respostas Esperadas**:
```json
// Mensagem de boas-vindas de teste de nó
{
  "status": "connected",
  "message": "WebSocket connection established",
  "endpoint": "/ws/test_node",
  "timestamp": "2025-08-17T22:53:08.581380+00:00"
}

// Echo de teste
{
  "type": "test_response",
  "echo": {
    "test_action": "node_test",
    "node_id": "test_node_001",
    "node_type": "security",
    "timestamp": 1755471188.5824354
  },
  "timestamp": "2025-08-17T22:53:08.582953+00:00"
}
```

## 🌐 Comunicação Entre WebSockets

### **Conceito**

A ATous Secure Network suporta comunicação entre múltiplos WebSockets simultaneamente, permitindo:

- 🔌 **Conexões Múltiplas**: Conectar a vários WebSockets ao mesmo tempo
- 📨 **Roteamento**: Roteamento automático de mensagens entre WebSockets
- 🔄 **Sincronização**: Sincronização de mensagens entre conexões
- 📊 **Broadcast**: Envio de mensagens para múltiplos WebSockets

### **Exemplo de Implementação**

```javascript
// Conectar a múltiplos WebSockets
const ws1 = new WebSocket('ws://127.0.0.1:8000/ws');
const ws2 = new WebSocket('ws://127.0.0.1:8000/api/ws');

// Configurar handlers para ambos
ws1.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('WS1 recebeu:', data);
};

ws2.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('WS2 recebeu:', data);
};

// Enviar mensagem do WS1 para WS2
ws1.send(JSON.stringify({
  from: 'ws1',
  to: 'ws2',
  message: 'Hello from WS1!',
  timestamp: Date.now()
}));

// Enviar resposta do WS2
ws2.send(JSON.stringify({
  from: 'ws2',
  to: 'ws1',
  message: 'Hello back from WS2!',
  timestamp: Date.now()
}));
```

### **Padrões de Mensagem**

#### **Mensagem de Roteamento**
```json
{
  "from": "ws1",
  "to": "ws2",
  "message": "Conteúdo da mensagem",
  "timestamp": 1755471188.5978405,
  "type": "routing"
}
```

#### **Mensagem de Broadcast**
```json
{
  "from": "controller",
  "to": "all",
  "message": "Mensagem para todos",
  "timestamp": 1755471188.5978405,
  "type": "broadcast"
}
```

#### **Mensagem de Status**
```json
{
  "from": "system",
  "to": "ws1",
  "message": "Status atualizado",
  "timestamp": 1755471188.5978405,
  "type": "status",
  "data": {
    "status": "operational",
    "connections": 5
  }
}
```

## 🔐 Criptografia via WebSocket

### **Funcionalidades**

A ATous Secure Network oferece criptografia integrada aos WebSockets:

- ✅ **Criptografia em Tempo Real**: Criptografia de mensagens instantânea
- 📨 **Descriptografia**: Descriptografia de mensagens criptografadas
- 🔐 **Múltiplos Algoritmos**: Suporte a AES-256 e outros algoritmos
- 📊 **Chaves Seguras**: Gerenciamento seguro de chaves
- 🛡️ **Auditoria**: Logs de operações criptográficas

### **Exemplo de Uso**

#### **Solicitar Criptografia**
```javascript
// Enviar pedido de criptografia
ws.send(JSON.stringify({
  action: 'encrypt',
  data: 'Dados sensíveis para criptografia',
  algorithm: 'AES-256',
  key_id: 'secure-key-001',
  timestamp: Date.now()
}));
```

#### **Solicitar Descriptografia**
```javascript
// Enviar pedido de descriptografia
ws.send(JSON.stringify({
  action: 'decrypt',
  encrypted_data: 'dados_criptografados_exemplo',
  algorithm: 'AES-256',
  key_id: 'secure-key-001',
  timestamp: Date.now()
}));
```

### **Respostas de Criptografia**

#### **Resposta de Criptografia**
```json
{
  "type": "response",
  "echo": {
    "action": "encrypt",
    "data": "Dados sensíveis para criptografia",
    "algorithm": "AES-256",
    "key_id": "secure-key-001",
    "timestamp": 1755471188.6044672
  },
  "timestamp": "2025-08-17T22:53:08.605919+00:00",
  "encryption_result": {
    "encrypted_data": "dados_criptografados_hash",
    "algorithm_used": "AES-256",
    "key_id": "secure-key-001",
    "encryption_time": "0.001s"
  }
}
```

#### **Resposta de Descriptografia**
```json
{
  "type": "response",
  "echo": {
    "action": "decrypt",
    "encrypted_data": "dados_criptografados_exemplo",
    "algorithm": "AES-256",
    "key_id": "secure-key-001",
    "timestamp": 1755471188.6073701
  },
  "timestamp": "2025-08-17T22:53:08.609800+00:00",
  "decryption_result": {
    "decrypted_data": "dados_originais",
    "algorithm_used": "AES-256",
    "key_id": "secure-key-001",
    "decryption_time": "0.001s",
    "integrity_verified": true
  }
}
```

## 🛡️ Segurança e Autenticação

### **Níveis de Segurança**

#### **1. Nível Básico** - `/websocket`
- ✅ Conexões não criptografadas
- ✅ Validação básica de entrada
- ✅ Rate limiting padrão
- ✅ Logs básicos

#### **2. Nível Padrão** - `/ws`
- ✅ Conexões criptografadas opcionais
- ✅ Validação de entrada
- ✅ Rate limiting configurável
- ✅ Logs detalhados

#### **3. Nível Aprimorado** - `/api/ws`
- ✅ Conexões criptografadas recomendadas
- ✅ Validação rigorosa de entrada
- ✅ Rate limiting estrito
- ✅ Logs de auditoria

#### **4. Nível de Monitoramento** - `/ws/test_node`
- ✅ Conexões criptografadas obrigatórias
- ✅ Validação máxima de entrada
- ✅ Rate limiting restritivo
- ✅ Logs de segurança completos

### **Configurações de Segurança**

#### **Rate Limiting**
```json
{
  "rate_limiting": {
    "enabled": true,
    "max_messages_per_minute": 1000,
    "max_connections_per_ip": 5,
    "block_duration": 300
  }
}
```

#### **Validação de Entrada**
```json
{
  "input_validation": {
    "enabled": true,
    "max_message_size": 1048576,
    "allowed_content_types": ["json", "text"],
    "sanitization_enabled": true
  }
}
```

#### **Criptografia**
```json
{
  "encryption": {
    "enabled": true,
    "default_algorithm": "AES-256",
    "key_rotation": 3600,
    "integrity_check": true
  }
}
```

## 📱 Exemplos de Clientes

### **JavaScript (Browser)**

```html
<!DOCTYPE html>
<html>
<head>
    <title>WebSocket Test</title>
</head>
<body>
    <h1>WebSocket Test - ATous Secure Network</h1>
    
    <div>
        <button onclick="connect()">Conectar</button>
        <button onclick="disconnect()">Desconectar</button>
        <button onclick="sendMessage()">Enviar Mensagem</button>
    </div>
    
    <div>
        <input type="text" id="messageInput" placeholder="Digite sua mensagem">
    </div>
    
    <div id="output"></div>
    
    <script>
        let ws = null;
        
        function connect() {
            ws = new WebSocket('ws://127.0.0.1:8000/ws');
            
            ws.onopen = () => {
                log('Conectado ao WebSocket!');
            };
            
            ws.onmessage = (event) => {
                const data = JSON.parse(event.data);
                log('Recebido: ' + JSON.stringify(data, null, 2));
            };
            
            ws.onclose = () => {
                log('Desconectado do WebSocket');
            };
            
            ws.onerror = (error) => {
                log('Erro: ' + error);
            };
        }
        
        function disconnect() {
            if (ws) {
                ws.close();
                ws = null;
            }
        }
        
        function sendMessage() {
            if (ws && ws.readyState === WebSocket.OPEN) {
                const message = document.getElementById('messageInput').value;
                ws.send(message);
                log('Enviado: ' + message);
            }
        }
        
        function log(message) {
            const output = document.getElementById('output');
            output.innerHTML += '<div>' + new Date().toLocaleTimeString() + ': ' + message + '</div>';
        }
    </script>
</body>
</html>
```

### **Node.js**

```javascript
const WebSocket = require('ws');

class WebSocketClient {
    constructor(url) {
        this.url = url;
        this.ws = null;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
    }
    
    connect() {
        try {
            this.ws = new WebSocket(this.url);
            
            this.ws.on('open', () => {
                console.log('Conectado ao WebSocket:', this.url);
                this.reconnectAttempts = 0;
            });
            
            this.ws.on('message', (data) => {
                try {
                    const message = JSON.parse(data);
                    console.log('Mensagem recebida:', message);
                    this.handleMessage(message);
                } catch (error) {
                    console.log('Texto recebido:', data.toString());
                }
            });
            
            this.ws.on('close', () => {
                console.log('WebSocket desconectado');
                this.attemptReconnect();
            });
            
            this.ws.on('error', (error) => {
                console.error('Erro no WebSocket:', error);
            });
            
        } catch (error) {
            console.error('Erro ao conectar:', error);
        }
    }
    
    send(data) {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            if (typeof data === 'string') {
                this.ws.send(data);
            } else {
                this.ws.send(JSON.stringify(data));
            }
            console.log('Mensagem enviada:', data);
        } else {
            console.error('WebSocket não está conectado');
        }
    }
    
    handleMessage(message) {
        // Processar mensagens recebidas
        switch (message.type) {
            case 'response':
                console.log('Echo recebido:', message.echo);
                break;
            case 'text_echo':
                console.log('Texto ecoado:', message.echo);
                break;
            default:
                console.log('Mensagem desconhecida:', message);
        }
    }
    
    attemptReconnect() {
        if (this.reconnectAttempts < this.maxReconnectAttempts) {
            this.reconnectAttempts++;
            console.log(`Tentativa de reconexão ${this.reconnectAttempts}/${this.maxReconnectAttempts}`);
            
            setTimeout(() => {
                this.connect();
            }, 5000 * this.reconnectAttempts);
        } else {
            console.error('Máximo de tentativas de reconexão atingido');
        }
    }
    
    disconnect() {
        if (this.ws) {
            this.ws.close();
            this.ws = null;
        }
    }
}

// Exemplo de uso
const client = new WebSocketClient('ws://127.0.0.1:8000/ws');
client.connect();

// Enviar mensagem após conexão
setTimeout(() => {
    client.send({
        action: 'test',
        message: 'Hello from Node.js!',
        timestamp: Date.now()
    });
    
    client.send('Mensagem de texto simples');
}, 1000);

// Desconectar após 10 segundos
setTimeout(() => {
    client.disconnect();
}, 10000);
```

### **Python**

```python
import asyncio
import websockets
import json
import time
from datetime import datetime

class WebSocketClient:
    def __init__(self, uri):
        self.uri = uri
        self.websocket = None
        self.reconnect_attempts = 0
        self.max_reconnect_attempts = 5
        
    async def connect(self):
        try:
            self.websocket = await websockets.connect(self.uri)
            print(f"Conectado ao WebSocket: {self.uri}")
            self.reconnect_attempts = 0
            return True
        except Exception as e:
            print(f"Erro ao conectar: {e}")
            return False
    
    async def send(self, data):
        if self.websocket and self.websocket.open:
            if isinstance(data, str):
                await self.websocket.send(data)
            else:
                await self.websocket.send(json.dumps(data))
            print(f"Mensagem enviada: {data}")
        else:
            print("WebSocket não está conectado")
    
    async def receive(self):
        if self.websocket and self.websocket.open:
            try:
                message = await self.websocket.recv()
                try:
                    data = json.loads(message)
                    print(f"Mensagem JSON recebida: {data}")
                    return data
                except json.JSONDecodeError:
                    print(f"Texto recebido: {message}")
                    return message
            except Exception as e:
                print(f"Erro ao receber mensagem: {e}")
                return None
        return None
    
    async def handle_message(self, message):
        if isinstance(message, dict):
            message_type = message.get('type', 'unknown')
            if message_type == 'response':
                echo = message.get('echo', {})
                print(f"Echo recebido: {echo}")
            elif message_type == 'text_echo':
                echo = message.get('echo', '')
                print(f"Texto ecoado: {echo}")
            else:
                print(f"Mensagem desconhecida: {message}")
        else:
            print(f"Texto recebido: {message}")
    
    async def attempt_reconnect(self):
        if self.reconnect_attempts < self.max_reconnect_attempts:
            self.reconnect_attempts += 1
            print(f"Tentativa de reconexão {self.reconnect_attempts}/{self.max_reconnect_attempts}")
            
            await asyncio.sleep(5 * self.reconnect_attempts)
            return await self.connect()
        else:
            print("Máximo de tentativas de reconexão atingido")
            return False
    
    async def close(self):
        if self.websocket:
            await self.websocket.close()
            self.websocket = None

async def main():
    client = WebSocketClient('ws://127.0.0.1:8000/ws')
    
    # Conectar
    if await client.connect():
        # Receber mensagem de boas-vindas
        welcome = await client.receive()
        await client.handle_message(welcome)
        
        # Enviar mensagem JSON
        await client.send({
            'action': 'test',
            'message': 'Hello from Python!',
            'timestamp': time.time()
        })
        
        # Receber resposta
        response = await client.receive()
        await client.handle_message(response)
        
        # Enviar texto simples
        await client.send('Mensagem de texto simples')
        
        # Receber resposta de texto
        text_response = await client.receive()
        await client.handle_message(text_response)
        
        # Aguardar um pouco
        await asyncio.sleep(2)
        
        # Fechar conexão
        await client.close()

if __name__ == "__main__":
    asyncio.run(main())
```

## 🚀 Melhores Práticas

### **1. Gerenciamento de Conexões**

- ✅ **Reconexão Automática**: Implementar lógica de reconexão automática
- ✅ **Heartbeat**: Enviar mensagens de heartbeat para manter conexões ativas
- ✅ **Pool de Conexões**: Gerenciar múltiplas conexões eficientemente
- ✅ **Timeout**: Configurar timeouts apropriados para conexões

### **2. Tratamento de Erros**

- ✅ **Try-Catch**: Sempre envolver operações WebSocket em try-catch
- ✅ **Logs**: Registrar todos os erros e eventos importantes
- ✅ **Fallback**: Implementar mecanismos de fallback para falhas
- ✅ **Validação**: Validar mensagens antes de enviar

### **3. Performance**

- ✅ **Mensagens Eficientes**: Minimizar tamanho das mensagens
- ✅ **Compressão**: Usar compressão quando apropriado
- ✅ **Batch**: Agrupar mensagens quando possível
- ✅ **Cache**: Implementar cache para mensagens frequentes

### **4. Segurança**

- ✅ **Criptografia**: Sempre usar criptografia para dados sensíveis
- ✅ **Autenticação**: Implementar autenticação quando necessário
- ✅ **Validação**: Validar todas as mensagens recebidas
- ✅ **Rate Limiting**: Respeitar limites de taxa configurados

## 📚 Recursos Adicionais

### **Documentação da API**
- [Swagger UI](http://127.0.0.1:8000/docs) - Documentação interativa da API
- [ReDoc](http://127.0.0.1:8000/redoc) - Documentação alternativa da API

### **Exemplos e Testes**
- [Collection Postman](docs/collection.json) - Coleção completa para testes
- [Scripts de Teste](test_websockets.py) - Scripts Python para testes automatizados

### **Configuração e Deploy**
- [Guia de Desenvolvedor](docs/DEVELOPER_GUIDE.md) - Configuração e desenvolvimento
- [Guia de Usuário](docs/USER_GUIDE.md) - Uso e operação do sistema

### **Suporte e Comunidade**
- [Issues GitHub](https://github.com/atous/secure-network/issues) - Reportar bugs e solicitar features
- [Discussions](https://github.com/atous/secure-network/discussions) - Discussões e suporte da comunidade

---

**ATous Secure Network** - Sistema de Segurança Inteligente com WebSockets Avançados 🚀
