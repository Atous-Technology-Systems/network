# Contratos de API - Atous Secure Network

> Criado em: 2025-07-30
>
> Este documento define os contratos de API para os diferentes componentes do sistema Atous Secure Network.
>
> Estado: MVP. Nem todos os contratos possuem endpoints HTTP implementados ainda. Endpoints efetivamente expostos no servidor estão descritos em `docs/technical/API_DOCUMENTATION.md` e no código `atous_sec_network/api/server.py` e `atous_sec_network/api/routes/*`.

## Sumário

1. [API do Model Manager](#1-api-do-model-manager)
2. [API do Sistema ABISS](#2-api-do-sistema-abiss)
3. [API do Sistema NNIS](#3-api-do-sistema-nnis)
4. [API do LoRa Optimizer](#4-api-do-lora-optimizer)
5. [API do P2P Recovery System](#5-api-do-p2p-recovery-system)
6. [API de Integração LLM](#6-api-de-integração-llm)

---

## 1. API do Model Manager

### 1.1 Verificação de Versão

**Endpoint (planejado):** `/model-version`

**Método:** GET

**Descrição:** Verifica a versão mais recente do modelo disponível no servidor de agregação.

**Parâmetros de Consulta:**
- `node_id` (string, obrigatório): Identificador único do nó solicitante
- `current_version` (integer, obrigatório): Versão atual do modelo no nó
- `model_type` (string, opcional): Tipo do modelo (padrão: "default")

**Resposta:**
```json
{
  "latest_version": 5,
  "update_available": true,
  "update_required": false,
  "update_url": "/model-diff/4/5",
  "full_model_url": "/model-full/5",
  "metadata": {
    "release_date": "2025-07-15T10:30:00Z",
    "size_bytes": 12500000,
    "diff_size_bytes": 250000,
    "release_notes": "Improved anomaly detection for industrial environments"
  }
}
```

**Códigos de Status:**
- `200 OK`: Requisição bem-sucedida
- `400 Bad Request`: Parâmetros inválidos
- `401 Unauthorized`: Autenticação necessária
- `403 Forbidden`: Nó não autorizado
- `404 Not Found`: Modelo não encontrado
- `500 Internal Server Error`: Erro no servidor

### 1.2 Obtenção de Patch de Modelo

**Endpoint (planejado):** `/model-diff/{from_version}/{to_version}`

**Método:** GET

**Descrição:** Obtém um patch binário para atualizar o modelo da versão `from_version` para `to_version`.

**Parâmetros de Caminho:**
- `from_version` (integer, obrigatório): Versão atual do modelo
- `to_version` (integer, obrigatório): Versão de destino do modelo

**Parâmetros de Consulta:**
- `node_id` (string, obrigatório): Identificador único do nó solicitante
- `model_type` (string, opcional): Tipo do modelo (padrão: "default")
- `format` (string, opcional): Formato do patch ("bsdiff", "custom") (padrão: "bsdiff")

**Resposta:**
- Conteúdo binário do patch com Content-Type `application/octet-stream`
- Headers:
  - `X-Checksum-SHA256`: Hash SHA-256 do patch
  - `X-Original-Size`: Tamanho do modelo original em bytes
  - `X-Patched-Size`: Tamanho esperado após aplicação do patch em bytes
  - `X-Encryption`: Algoritmo de criptografia usado (se aplicável)

**Códigos de Status:**
- `200 OK`: Requisição bem-sucedida
- `400 Bad Request`: Parâmetros inválidos
- `401 Unauthorized`: Autenticação necessária
- `403 Forbidden`: Nó não autorizado
- `404 Not Found`: Versão do modelo não encontrada
- `500 Internal Server Error`: Erro no servidor

### 1.3 Obtenção de Modelo Completo

**Endpoint (planejado):** `/model-full/{version}`

**Método:** GET

**Descrição:** Obtém o modelo completo na versão especificada.

**Parâmetros de Caminho:**
- `version` (integer, obrigatório): Versão do modelo a ser obtida

**Parâmetros de Consulta:**
- `node_id` (string, obrigatório): Identificador único do nó solicitante
- `model_type` (string, opcional): Tipo do modelo (padrão: "default")
- `format` (string, opcional): Formato do modelo ("pytorch", "onnx") (padrão: "pytorch")

**Resposta:**
- Conteúdo binário do modelo com Content-Type `application/octet-stream`
- Headers:
  - `X-Checksum-SHA256`: Hash SHA-256 do modelo
  - `X-Model-Size`: Tamanho do modelo em bytes
  - `X-Model-Format`: Formato do modelo
  - `X-Encryption`: Algoritmo de criptografia usado (se aplicável)

**Códigos de Status:**
- `200 OK`: Requisição bem-sucedida
- `400 Bad Request`: Parâmetros inválidos
- `401 Unauthorized`: Autenticação necessária
- `403 Forbidden`: Nó não autorizado
- `404 Not Found`: Versão do modelo não encontrada
- `500 Internal Server Error`: Erro no servidor

---

## 2. API do Sistema ABISS

### 2.1 Submissão de Dados Comportamentais

**Endpoint (planejado):** `/abiss/behavior`

**Método:** POST

**Descrição:** Submete dados comportamentais de um nó para análise pelo sistema ABISS.

**Corpo da Requisição:**
```json
{
  "node_id": "node123",
  "timestamp": "2025-07-30T15:45:30Z",
  "behavior_data": {
    "traffic_pattern": [32, 45, 12, 67, 89, 23],
    "connection_frequency": 12.5,
    "packet_sizes": [128, 256, 128, 512],
    "active_hours": [1, 0, 1, 1, 0, 0, 1, 1],
    "resource_usage": {
      "cpu": 0.45,
      "memory": 0.32,
      "network": 0.67
    },
    "api_calls": [
      {"endpoint": "/data", "count": 23, "avg_latency": 45.6},
      {"endpoint": "/status", "count": 12, "avg_latency": 12.3}
    ]
  },
  "context": {
    "environment": "industrial",
    "firmware_version": "2.3.1",
    "uptime_hours": 720
  }
}
```

**Resposta:**
```json
{
  "analysis_id": "abiss-2025073015453012",
  "timestamp": "2025-07-30T15:45:35Z",
  "result": {
    "anomaly_detected": false,
    "confidence": 0.98,
    "threat_score": 0.03,
    "profile_updated": true
  },
  "recommendations": [
    {
      "type": "info",
      "message": "Comportamento normal detectado"
    }
  ]
}
```

**Códigos de Status:**
- `200 OK`: Requisição bem-sucedida
- `202 Accepted`: Dados aceitos para processamento assíncrono
- `400 Bad Request`: Dados inválidos
- `401 Unauthorized`: Autenticação necessária
- `403 Forbidden`: Nó não autorizado
- `500 Internal Server Error`: Erro no servidor

### 2.2 Consulta de Perfil Comportamental

**Endpoint (planejado):** `/abiss/profile/{node_id}`

**Método:** GET

**Descrição:** Obtém o perfil comportamental atual de um nó específico.

**Parâmetros de Caminho:**
- `node_id` (string, obrigatório): Identificador único do nó

**Resposta:**
```json
{
  "node_id": "node123",
  "profile_created": "2025-06-15T10:30:00Z",
  "profile_updated": "2025-07-30T15:45:35Z",
  "data_points": 1458,
  "baseline": {
    "traffic_pattern": [25.3, 42.1, 15.7, 62.4, 85.2, 20.1],
    "connection_frequency": 10.2,
    "packet_sizes_distribution": {
      "small": 0.35,
      "medium": 0.45,
      "large": 0.20
    },
    "active_hours_pattern": [0.9, 0.1, 0.8, 0.9, 0.2, 0.1, 0.8, 0.9]
  },
  "anomaly_history": [
    {
      "timestamp": "2025-07-10T08:12:45Z",
      "threat_score": 0.75,
      "description": "Padrão de tráfego anômalo",
      "resolution": "Falso positivo - Manutenção programada"
    }
  ]
}
```

**Códigos de Status:**
- `200 OK`: Requisição bem-sucedida
- `400 Bad Request`: Parâmetros inválidos
- `401 Unauthorized`: Autenticação necessária
- `403 Forbidden`: Acesso não autorizado
- `404 Not Found`: Perfil não encontrado
- `500 Internal Server Error`: Erro no servidor

---

## 3. API do Sistema NNIS

### 3.1 Consulta de Memória Imunológica

**Endpoint (planejado):** `/nnis/memory`

**Método:** GET

**Descrição:** Obtém informações sobre a memória imunológica do sistema NNIS.

**Parâmetros de Consulta:**
- `threat_type` (string, opcional): Filtrar por tipo de ameaça
- `limit` (integer, opcional): Número máximo de registros (padrão: 50)
- `offset` (integer, opcional): Deslocamento para paginação (padrão: 0)

**Resposta:**
```json
{
  "total_records": 127,
  "returned_records": 50,
  "memory_cells": [
    {
      "id": "mc-12345",
      "threat_type": "ddos",
      "signature": "high_frequency_small_packets",
      "created": "2025-06-10T14:30:00Z",
      "last_triggered": "2025-07-25T08:15:30Z",
      "trigger_count": 3,
      "confidence": 0.95,
      "response": {
        "type": "block",
        "duration_minutes": 30,
        "effectiveness": 0.98
      }
    },
    {
      "id": "mc-12346",
      "threat_type": "data_exfiltration",
      "signature": "unusual_outbound_traffic_pattern",
      "created": "2025-06-15T09:45:00Z",
      "last_triggered": "2025-07-20T22:10:15Z",
      "trigger_count": 2,
      "confidence": 0.87,
      "response": {
        "type": "rate_limit",
        "threshold": 100,
        "effectiveness": 0.75
      }
    }
  ]
}
```

**Códigos de Status:**
- `200 OK`: Requisição bem-sucedida
- `400 Bad Request`: Parâmetros inválidos
- `401 Unauthorized`: Autenticação necessária
- `403 Forbidden`: Acesso não autorizado
- `500 Internal Server Error`: Erro no servidor

### 3.2 Ativação de Resposta Imune

**Endpoint (planejado):** `/nnis/response`

**Método:** POST

**Descrição:** Ativa manualmente uma resposta imune para uma ameaça detectada.

**Corpo da Requisição:**
```json
{
  "node_id": "node123",
  "threat_type": "intrusion",
  "threat_data": {
    "signature": "unauthorized_api_access",
    "confidence": 0.92,
    "source_ip": "192.168.1.100",
    "timestamp": "2025-07-30T16:20:45Z",
    "details": {
      "endpoint": "/admin/config",
      "method": "POST",
      "user_agent": "Mozilla/5.0 (compatible; Scanner/1.0)"
    }
  },
  "suggested_response": {
    "type": "block",
    "duration_minutes": 60
  }
}
```

**Resposta:**
```json
{
  "response_id": "resp-78901",
  "timestamp": "2025-07-30T16:20:50Z",
  "status": "activated",
  "memory_cell_created": true,
  "memory_cell_id": "mc-34567",
  "actions_taken": [
    {
      "type": "block",
      "target": "192.168.1.100",
      "duration_minutes": 60,
      "status": "success"
    },
    {
      "type": "alert",
      "severity": "high",
      "message": "Intrusion attempt blocked",
      "status": "success"
    }
  ],
  "expiration": "2025-07-30T17:20:50Z"
}
```

**Códigos de Status:**
- `200 OK`: Requisição bem-sucedida
- `202 Accepted`: Resposta aceita para processamento assíncrono
- `400 Bad Request`: Dados inválidos
- `401 Unauthorized`: Autenticação necessária
- `403 Forbidden`: Acesso não autorizado
- `500 Internal Server Error`: Erro no servidor

---

## 4. API do LoRa Optimizer

### 4.1 Obtenção de Parâmetros Otimizados

**Endpoint (planejado):** `/lora/optimize`

**Método:** POST

**Descrição:** Obtém parâmetros LoRa otimizados com base nas condições fornecidas.

**Corpo da Requisição:**
```json
{
  "node_id": "node123",
  "environment": "industrial",
  "distance_km": 2.5,
  "region": "EU868",
  "power_constraint": "battery",
  "priority": {
    "reliability": 0.7,
    "throughput": 0.2,
    "power_efficiency": 0.1
  },
  "current_metrics": {
    "rssi": -100,
    "snr": 5.2,
    "packet_loss": 0.15,
    "battery_level": 0.65
  }
}
```

**Resposta:**
```json
{
  "optimization_id": "opt-56789",
  "timestamp": "2025-07-30T16:30:00Z",
  "parameters": {
    "spreading_factor": 10,
    "bandwidth": 125,
    "coding_rate": "4/5",
    "tx_power": 14,
    "preamble_length": 8,
    "frequency": 868.1,
    "implicit_header": false
  },
  "expected_performance": {
    "range_km": 3.2,
    "airtime_ms": 205.8,
    "data_rate_bps": 980,
    "packet_loss_estimate": 0.05,
    "battery_impact": "medium"
  },
  "recommendations": [
    {
      "type": "info",
      "message": "Parâmetros otimizados para confiabilidade em ambiente industrial"
    },
    {
      "type": "warning",
      "message": "Considere aumentar a altura da antena para melhorar alcance"
    }
  ]
}
```

**Códigos de Status:**
- `200 OK`: Requisição bem-sucedida
- `400 Bad Request`: Dados inválidos
- `401 Unauthorized`: Autenticação necessária
- `403 Forbidden`: Acesso não autorizado
- `500 Internal Server Error`: Erro no servidor

### 4.2 Submissão de Métricas de Canal

**Endpoint (planejado):** `/lora/metrics`

**Método:** POST

**Descrição:** Submete métricas de canal LoRa para análise e otimização contínua.

**Corpo da Requisição:**
```json
{
  "node_id": "node123",
  "timestamp": "2025-07-30T16:35:00Z",
  "parameters": {
    "spreading_factor": 10,
    "bandwidth": 125,
    "coding_rate": "4/5",
    "tx_power": 14,
    "frequency": 868.1
  },
  "metrics": {
    "rssi": -102,
    "snr": 4.8,
    "packet_loss": 0.08,
    "throughput_bps": 950,
    "battery_drain_mah": 12.5,
    "latency_ms": 220
  },
  "environment_data": {
    "temperature": 25.3,
    "humidity": 65.2,
    "weather": "clear",
    "obstacles": "buildings"
  }
}
```

**Resposta:**
```json
{
  "receipt_id": "rcpt-90123",
  "timestamp": "2025-07-30T16:35:05Z",
  "status": "accepted",
  "optimization_available": true,
  "optimization_url": "/lora/optimize?node_id=node123"
}
```

**Códigos de Status:**
- `200 OK`: Requisição bem-sucedida
- `202 Accepted`: Métricas aceitas para processamento assíncrono
- `400 Bad Request`: Dados inválidos
- `401 Unauthorized`: Autenticação necessária
- `403 Forbidden`: Acesso não autorizado
- `500 Internal Server Error`: Erro no servidor

---

## 5. API do P2P Recovery System

### 5.1 Consulta de Status de Nó

**Endpoint (planejado):** `/p2p/node/{node_id}/status`

**Método:** GET

**Descrição:** Obtém o status atual de um nó específico na rede P2P.

**Parâmetros de Caminho:**
- `node_id` (string, obrigatório): Identificador único do nó

**Resposta:**
```json
{
  "node_id": "node123",
  "status": "active",
  "last_seen": "2025-07-30T16:40:15Z",
  "uptime_hours": 720.5,
  "health_score": 0.98,
  "role": "regular",
  "connections": 5,
  "services": [
    {
      "id": "data-replication",
      "status": "running",
      "health": "good"
    },
    {
      "id": "model-serving",
      "status": "running",
      "health": "good"
    }
  ],
  "resources": {
    "cpu_usage": 0.35,
    "memory_usage": 0.42,
    "disk_usage": 0.28,
    "battery_level": 0.85
  }
}
```

**Códigos de Status:**
- `200 OK`: Requisição bem-sucedida
- `400 Bad Request`: Parâmetros inválidos
- `401 Unauthorized`: Autenticação necessária
- `403 Forbidden`: Acesso não autorizado
- `404 Not Found`: Nó não encontrado
- `500 Internal Server Error`: Erro no servidor

### 5.2 Inicialização de Recuperação

**Endpoint (planejado):** `/p2p/recovery`

**Método:** POST

**Descrição:** Inicia um processo de recuperação para um nó que foi reiniciado ou restaurado.

**Corpo da Requisição:**
```json
{
  "node_id": "node123",
  "recovery_type": "full",
  "last_known_state": {
    "timestamp": "2025-07-29T10:15:30Z",
    "version": "2.3.1",
    "services": ["data-replication", "model-serving"],
    "data_shards": ["shard-001", "shard-005", "shard-012"]
  },
  "available_resources": {
    "storage_bytes": 1073741824,
    "memory_bytes": 536870912,
    "cpu_cores": 4
  }
}
```

**Resposta:**
```json
{
  "recovery_id": "rec-45678",
  "timestamp": "2025-07-30T16:45:00Z",
  "status": "initiated",
  "estimated_completion": "2025-07-30T16:50:00Z",
  "recovery_plan": {
    "steps": [
      {
        "type": "network_rejoin",
        "status": "in_progress",
        "estimated_duration_seconds": 30
      },
      {
        "type": "data_recovery",
        "status": "pending",
        "estimated_duration_seconds": 180,
        "shards": ["shard-001", "shard-005", "shard-012"]
      },
      {
        "type": "service_restoration",
        "status": "pending",
        "estimated_duration_seconds": 90,
        "services": ["data-replication", "model-serving"]
      }
    ]
  },
  "recovery_url": "/p2p/recovery/rec-45678"
}
```

**Códigos de Status:**
- `200 OK`: Requisição bem-sucedida
- `202 Accepted`: Recuperação iniciada assincronamente
- `400 Bad Request`: Dados inválidos
- `401 Unauthorized`: Autenticação necessária
- `403 Forbidden`: Acesso não autorizado
- `500 Internal Server Error`: Erro no servidor

---

## 6. API de Integração LLM

### 6.1 Submissão de Contexto para Análise

**Endpoint:** `/llm/context`

**Método:** POST

**Descrição:** Submete um contexto de um modelo SLM (Small Language Model) para análise por um LLM (Large Language Model).

**Corpo da Requisição:**
```json
{
  "node_id": "node123",
  "timestamp": "2025-07-30T16:50:00Z",
  "context_type": "security_event",
  "context_data": {
    "summary": "Padrão de acesso incomum detectado",
    "confidence": 0.82,
    "local_analysis": "Possível tentativa de acesso não autorizado",
    "event_features": [
      {"name": "access_frequency", "value": 12.5, "normal_range": [0.5, 5.0]},
      {"name": "time_pattern", "value": "overnight", "normal_value": "business_hours"},
      {"name": "source_diversity", "value": 0.15, "normal_range": [0.5, 1.0]}
    ],
    "raw_data_hash": "sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
  },
  "query": "Analisar se este padrão representa uma ameaça real ou um falso positivo"
}
```

**Resposta:**
```json
{
  "analysis_id": "llm-67890",
  "timestamp": "2025-07-30T16:50:10Z",
  "status": "completed",
  "analysis": {
    "conclusion": "Provável ameaça real",
    "confidence": 0.95,
    "reasoning": "O padrão apresenta múltiplos indicadores de comportamento anômalo: frequência de acesso muito acima do normal, ocorrência durante horário não comercial, e baixa diversidade de fontes (indicando possível origem única). Este conjunto de fatores é consistente com tentativas de força bruta ou varredura automatizada.",
    "recommendations": [
      "Implementar bloqueio temporário do IP de origem",
      "Aumentar requisitos de autenticação para este endpoint",
      "Monitorar por padrões similares em outros nós da rede"
    ],
    "similar_cases": [
      {
        "id": "case-12345",
        "similarity": 0.87,
        "outcome": "confirmed_threat"
      }
    ]
  },
  "model_info": {
    "name": "Gemma-7B-Security",
    "version": "2.1.0",
    "specialization": "security_analysis"
  }
}
```

**Códigos de Status:**
- `200 OK`: Requisição bem-sucedida
- `202 Accepted`: Contexto aceito para processamento assíncrono
- `400 Bad Request`: Dados inválidos
- `401 Unauthorized`: Autenticação necessária
- `403 Forbidden`: Acesso não autorizado
- `500 Internal Server Error`: Erro no servidor

### 6.2 Consulta de Análise LLM

**Endpoint:** `/llm/analysis/{analysis_id}`

**Método:** GET

**Descrição:** Obtém o resultado de uma análise LLM previamente solicitada.

**Parâmetros de Caminho:**
- `analysis_id` (string, obrigatório): Identificador único da análise

**Resposta:**
```json
{
  "analysis_id": "llm-67890",
  "timestamp": "2025-07-30T16:50:10Z",
  "status": "completed",
  "analysis": {
    "conclusion": "Provável ameaça real",
    "confidence": 0.95,
    "reasoning": "O padrão apresenta múltiplos indicadores de comportamento anômalo: frequência de acesso muito acima do normal, ocorrência durante horário não comercial, e baixa diversidade de fontes (indicando possível origem única). Este conjunto de fatores é consistente com tentativas de força bruta ou varredura automatizada.",
    "recommendations": [
      "Implementar bloqueio temporário do IP de origem",
      "Aumentar requisitos de autenticação para este endpoint",
      "Monitorar por padrões similares em outros nós da rede"
    ],
    "similar_cases": [
      {
        "id": "case-12345",
        "similarity": 0.87,
        "outcome": "confirmed_threat"
      }
    ]
  },
  "model_info": {
    "name": "Gemma-7B-Security",
    "version": "2.1.0",
    "specialization": "security_analysis"
  }
}
```

**Códigos de Status:**
- `200 OK`: Requisição bem-sucedida
- `202 Accepted`: Análise ainda em processamento
- `400 Bad Request`: Parâmetros inválidos
- `401 Unauthorized`: Autenticação necessária
- `403 Forbidden`: Acesso não autorizado
- `404 Not Found`: Análise não encontrada
- `500 Internal Server Error`: Erro no servidor

---

## Autenticação e Segurança

Todas as APIs requerem autenticação usando um dos seguintes métodos:

1. **API Key de Admin** — `X-Admin-Api-Key` (já disponível para rotas Admin quando `ADMIN_AUTH_ENABLED=true`)
2. **Token JWT** — Planejado
3. **mTLS** — Planejado para agentes

JWT e fluxo de refresh ainda não estão implementados no servidor.

Todas as comunicações devem ser realizadas via HTTPS (TLS 1.3+) com as seguintes configurações mínimas:
- Cifras: TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256
- Curvas: X25519, P-256, P-384
- Certificados: RSA-2048 ou EC-P256 no mínimo

## Limites de Taxa

As APIs implementam os seguintes limites de taxa por nó:

- Endpoints GET: 100 requisições por minuto
- Endpoints POST: 30 requisições por minuto
- Endpoints de análise LLM: 10 requisições por minuto

Exceder esses limites resultará em respostas `429 Too Many Requests` com o header `Retry-After` indicando o tempo de espera necessário.

## Versionamento

O versionamento da API é controlado pelo header `Accept` ou pelo parâmetro de consulta `api_version`.

Exemplo:
```
Accept: application/json; version=1.0
```
ou
```
/abiss/behavior?api_version=1.0
```

A versão atual da API é 1.0. Mudanças incompatíveis serão introduzidas em novas versões principais (2.0, 3.0, etc.).

---