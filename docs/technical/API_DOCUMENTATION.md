# ATous Secure Network - API Documentation

## API Overview

ATous Secure Network provides a comprehensive set of APIs for each subsystem. This documentation covers the public interfaces, usage patterns, and examples for all major components.

## Web API Endpoints

### Core Endpoints

#### Root Endpoint
- **URL**: `GET /`
- **Description**: Endpoint raiz com informações básicas da API
- **Response**: JSON com nome, versão, status e lista de endpoints disponíveis

#### Health Check
- **URL**: `GET /health`
- **Description**: Verificação de saúde de todos os sistemas
- **Response**: JSON com status dos sistemas (ABISS, NNIS, Model Manager) e métricas

#### API Information
- **URL**: `GET /api/info`
- **Description**: Informações detalhadas da API, features e endpoints
- **Response**: JSON com detalhes da API, funcionalidades habilitadas e lista completa de endpoints

#### Security Status
- **URL**: `GET /api/security/status`
- **Description**: Status dos sistemas de segurança ABISS e NNIS
- **Response**: JSON com status operacional dos sistemas de segurança

#### System Metrics
- **URL**: `GET /api/metrics`
- **Description**: Métricas do sistema incluindo uso de CPU, memória e estatísticas de segurança
- **Response**: JSON com métricas de sistema, API e segurança

#### Documentation
- **URL**: `GET /docs`
- **Description**: Interface Swagger UI para documentação interativa da API
- **URL**: `GET /redoc`
- **Description**: Interface ReDoc para documentação da API
- **URL**: `GET /openapi.json`
- **Description**: Schema OpenAPI em formato JSON

### Crypto Endpoints

#### Encryption Services
- **URL**: `POST /api/crypto/encrypt`
- **URL**: `POST /api/security/encrypt`
- **URL**: `POST /encrypt`
- **Description**: Endpoints de criptografia AES-256
- **Request Body**: JSON com dados para criptografar
- **Response**: JSON com dados criptografados

### WebSocket Endpoints

#### Real-time Communication
- **URL**: `WS /ws`
- **URL**: `WS /api/ws`
- **URL**: `WS /websocket`
- **URL**: `WS /ws/test_node`
- **Description**: WebSockets para comunicação em tempo real e testes
- **Features**: Conexão bidirecional, notificações de eventos de segurança

## Security APIs (nota de estado)

Algumas APIs de segurança estão disponíveis como endpoints de status e criptografia. Os contratos detalhados de ABISS/NNIS e LLM/policy/discovery/relay estão descritos em `docs/api-contracts.md` e alguns ainda não possuem endpoints HTTP dedicados; usam serviços in-memory no MVP. Para uma visão operacional completa das rotas, consulte o "Mapa de Endpoints": `docs/technical/ENDPOINTS_MAP.md`.

### ABISS System

#### Class: `ABISSSystem`
```python
class ABISSSystem:
    def __init__(self, config: Dict[str, Any]) -> None:
        """Initialize ABISS system with configuration.
        
        Args:
            config: Configuration dictionary containing:
                - threshold: float - Detection threshold
                - learning_rate: float - Model adaptation rate
                - update_interval: int - Model update frequency
        """

    def analyze_behavior(self, data: Dict[str, Any]) -> BehaviorResult:
        """Analyze system behavior for threats.
        
        Args:
            data: Dictionary containing behavioral data
                
        Returns:
            BehaviorResult with threat assessment
        """

    def handle_threat(self, threat: ThreatData) -> ResponseResult:
        """Handle detected security threat.
        
        Args:
            threat: ThreatData object describing the threat
            
        Returns:
            ResponseResult with action taken
        """
```

### NNIS System

#### Class: `NNISSystem`
```python
class NNISSystem:
    def __init__(self, config: Dict[str, Any]) -> None:
        """Initialize NNIS with configuration.
        
        Args:
            config: Configuration dictionary containing:
                - memory_size: int - Signature storage size
                - detection_threshold: float - Match threshold
                - response_timeout: int - Response wait time
        """

    def detect_antigens(self, data: bytes) -> List[AntigenMatch]:
        """Detect threat patterns in data.
        
        Args:
            data: Binary data to analyze
            
        Returns:
            List of AntigenMatch objects
        """

    def generate_response(self, antigen: AntigenMatch) -> ImmuneResponse:
        """Generate immune response to threat.
        
        Args:
            antigen: Matched threat pattern
            
        Returns:
            ImmuneResponse with actions
        """
```

## Network APIs

### LoRa Optimizer

#### Class: `LoraAdaptiveEngine`
```python
class LoraAdaptiveEngine:
    def __init__(self, base_config: Dict[str, Any], history_size: int = 100) -> None:
        """Initialize LoRa optimizer.
        
        Args:
            base_config: Initial LoRa configuration
            history_size: Metric history length
        """

    def log_metrics(self, rssi: float, snr: float, lost_packets: float) -> None:
        """Log channel metrics.
        
        Args:
            rssi: Signal strength (dBm)
            snr: Signal-to-noise ratio (dB)
            lost_packets: Loss rate (0-1)
        """

    def adjust_parameters(self) -> bool:
        """Optimize parameters based on conditions.
        
        Returns:
            True if parameters were adjusted
        """
```

### P2P Recovery

#### Class: `ChurnMitigation`
```python
class ChurnMitigation:
    def __init__(self, node_list: List[str], health_check_interval: int = 300) -> None:
        """Initialize P2P recovery system.
        
        Args:
            node_list: Initial network nodes
            health_check_interval: Check frequency (seconds)
        """

    def start_health_monitor(self) -> None:
        """Start node health monitoring."""

    def stop_health_monitor(self) -> None:
        """Stop health monitoring."""

    def handle_node_failure(self, node: str) -> None:
        """Handle node failure recovery.
        
        Args:
            node: Failed node ID
        """

    def detect_network_partitions(self) -> List[Set[str]]:
        """Detect network partitions.
        
        Returns:
            List of node sets representing partitions
        """
```

## Core APIs

### Model Manager

#### Class: `ModelManager`
```python
class ModelManager:
    def __init__(self, config: Dict[str, Any]) -> None:
        """Initialize model manager.
        
        Args:
            config: Configuration containing:
                - storage_path: str - Model storage location
                - version_control: bool - Enable versioning
                - auto_rollback: bool - Auto rollback on failure
        """

    def update_model(self, model_id: str, version: str) -> bool:
        """Update model to new version.
        
        Args:
            model_id: Model identifier
            version: Target version
            
        Returns:
            True if update successful
        """

    def rollback_model(self, model_id: str) -> bool:
        """Rollback model to previous version.
        
        Args:
            model_id: Model identifier
            
        Returns:
            True if rollback successful
        """
```

### LLM Integration

#### Class: `CognitivePipeline`
```python
class CognitivePipeline:
    def __init__(self, config: Dict[str, Any]) -> None:
        """Initialize cognitive pipeline.
        
        Args:
            config: Configuration containing:
                - model_config: Dict - Model settings
                - cache_config: Dict - Cache settings
                - pipeline_config: Dict - Processing settings
        """

    def process_context(self, input_data: Any) -> ProcessingResult:
        """Process input through pipeline.
        
        Args:
            input_data: Input data or context
            
        Returns:
            ProcessingResult with outputs
        """

    def update_context(self, context_data: Dict[str, Any]) -> None:
        """Update processing context.
        
        Args:
            context_data: New context information
        """
```

## Usage Examples

### Threat Detection
```python
# Initialize security systems
abiss = ABISSSystem(config={
    'threshold': 0.85,
    'learning_rate': 0.01,
    'update_interval': 300
})

nnis = NNISSystem(config={
    'memory_size': 10000,
    'detection_threshold': 0.75,
    'response_timeout': 60
})

# Monitor and respond to threats
behavior_data = {'network_traffic': [...], 'system_calls': [...]}
result = abiss.analyze_behavior(behavior_data)

if result.threat_detected:
    response = abiss.handle_threat(result.threat_data)
    immune_response = nnis.generate_response(response.antigen_signature)
```

### Network Optimization
```python
# Initialize network systems
lora = LoraAdaptiveEngine(base_config={
    'region': 'BR',
    'spreading_factor': 7,
    'tx_power': 14,
    'bandwidth': 125000
})

p2p = ChurnMitigation(node_list=['node1', 'node2', 'node3'])

# Start monitoring
p2p.start_health_monitor()

# Log metrics and optimize
lora.log_metrics(rssi=-75.0, snr=5.2, lost_packets=0.02)
if lora.adjust_parameters():
    print("Parameters optimized")
```

### Model Management
```python
# Initialize model systems
model_mgr = ModelManager(config={
    'storage_path': '/models',
    'version_control': True,
    'auto_rollback': True
})

pipeline = CognitivePipeline(config={
    'model_config': {...},
    'cache_config': {...},
    'pipeline_config': {...}
})

# Update model and process
if model_mgr.update_model('threat_detector', '2.0.0'):
    result = pipeline.process_context(input_data)
    pipeline.update_context({'new_threats': result.detected_threats})
```

## Error Handling

### Common Patterns
```python
try:
    # Network operation
    lora.adjust_parameters()
except NetworkError as e:
    logger.error(f"Network error: {e}")
    # Implement retry logic
except HardwareError as e:
    logger.error(f"Hardware error: {e}")
    # Fall back to simulation mode
finally:
    # Cleanup resources
```

### Best Practices
1. Always handle hardware exceptions
2. Implement retry logic for network operations
3. Use proper logging and monitoring
4. Include cleanup in finally blocks
5. Maintain system state consistency

## Testing

### Unit Tests
```python
def test_threat_detection():
    abiss = ABISSSystem(config={'threshold': 0.85})
    result = abiss.analyze_behavior(test_data)
    assert result.threat_detected == True
    assert result.confidence > 0.85

def test_parameter_optimization():
    lora = LoraAdaptiveEngine(test_config)
    lora.log_metrics(-75.0, 5.2, 0.02)
    assert lora.adjust_parameters() == True
```

### Integration Tests
```python
def test_security_integration():
    abiss = ABISSSystem(config)
    nnis = NNISSystem(config)
    
    threat = abiss.analyze_behavior(test_data)
    response = nnis.generate_response(threat.signature)
    
    assert response.is_valid
    assert response.matches_threat(threat)
