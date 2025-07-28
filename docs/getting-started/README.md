# Getting Started with Atous Secure Network

## Table of Contents

1. [Quick Start](#quick-start)
2. [Installation](#installation)
   - [Prerequisites](#prerequisites)
   - [Installation Methods](#installation-methods)
3. [Configuration](#configuration)
   - [Basic Configuration](#basic-configuration)
   - [Advanced Configuration](#advanced-configuration)
4. [Your First Network](#your-first-network)
   - [Starting a Coordinator Node](#starting-a-coordinator-node)
   - [Adding Worker Nodes](#adding-worker-nodes)
5. [Basic Operations](#basic-operations)
   - [Checking Node Status](#checking-node-status)
   - [Managing Models](#managing-models)
   - [Viewing Logs](#viewing-logs)
6. [Next Steps](#next-steps)

## Quick Start

### For the Impatient

1. Install the package:
   ```bash
   pip install atous-secure-network
   ```

2. Start a coordinator node:
   ```bash
   atous start --role coordinator --port 8000
   ```

3. In another terminal, start a worker node:
   ```bash
   atous start --role worker --coordinator http://localhost:8000
   ```

4. Verify the connection:
   ```bash
   curl http://localhost:8000/status
   ```

## Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Git (for development installation)
- (Optional) Virtual environment (recommended)

### Installation Methods

#### Using pip (Recommended)

```bash
pip install atous-secure-network
```

#### From Source

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/atous-secure-network.git
   cd atous-secure-network
   ```

2. Install in development mode:
   ```bash
   pip install -e .
   ```

#### Using Docker

```bash
docker pull yourusername/atous-network:latest
docker run -p 8000:8000 yourusername/atous-network
```

## Configuration

### Basic Configuration

Create a `config.yaml` file in your working directory:

```yaml
# Node Configuration
node:
  id: node1
  role: coordinator  # or 'worker'
  port: 8000
  host: 0.0.0.0

# Model Configuration
model:
  path: ./models/current_model.bin
  storage_path: ./storage
  max_versions: 5

# Network Configuration
network:
  bootstrap_nodes:
    - 192.168.1.100:8000
    - 192.168.1.101:8000
  discovery_interval: 60  # seconds

# Security Configuration
security:
  enable_encryption: true
  enable_auth: true
  auth_token: your-secure-token
```

### Advanced Configuration

#### Database Configuration

```yaml
database:
  type: postgresql  # or 'sqlite', 'mysql'
  host: localhost
  port: 5432
  name: atous_network
  user: postgres
  password: your-secure-password
  pool_size: 10
```

#### Redis Configuration (for caching)

```yaml
redis:
  host: localhost
  port: 6379
  db: 0
  password: your-redis-password
  max_connections: 20
```

## Your First Network

### Starting a Coordinator Node

1. Create a configuration file (`coordinator.yaml`):
   ```yaml
   node:
     id: coordinator-1
     role: coordinator
     port: 8000
   
   model:
     path: ./models/coordinator_model.bin
     storage_path: ./coordinator_storage
   ```

2. Start the coordinator:
   ```bash
   atous start --config coordinator.yaml
   ```

### Adding Worker Nodes

1. Create a configuration file for the worker (`worker1.yaml`):
   ```yaml
   node:
     id: worker-1
     role: worker
     port: 8001
   
   network:
     bootstrap_nodes:
       - localhost:8000  # Coordinator address
   
   model:
     path: ./models/worker1_model.bin
     storage_path: ./worker1_storage
   ```

2. Start the worker:
   ```bash
   atous start --config worker1.yaml
   ```

## Basic Operations

### Checking Node Status

```bash
# Using the CLI
atous status

# Or via HTTP API
curl http://localhost:8000/api/v1/status
```

### Managing Models

#### List Available Models

```bash
atous model list
```

#### Download a Model

```bash
atous model download --source http://example.com/model.bin --version 1.0.0
```

#### Rollback to Previous Version

```bash
atous model rollback --version 0.9.0
```

### Viewing Logs

#### View Application Logs

```bash
# Follow logs in real-time
tail -f logs/atous.log

# Filter logs by level
cat logs/atous.log | grep -i error
```

#### View System Metrics

```bash
# Using the CLI
atous metrics

# Or via HTTP API
curl http://localhost:8000/metrics
```

## Next Steps

1. Explore the [API Reference](../api-reference/README.md) for detailed API documentation
2. Learn about [Deployment Options](../deployment/README.md) for production environments
3. Check out the [Development Guide](../development/README.md) for contributing to the project
4. Join our community forum/slack for support and discussions

## Troubleshooting

### Common Issues

#### Node Fails to Start
- Check if the port is already in use
- Verify configuration file syntax
- Check log files for errors

#### Connection Issues
- Verify network connectivity between nodes
- Check firewall settings
- Ensure correct bootstrap node addresses

