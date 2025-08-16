# Deployment Guide

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Docker Deployment](#docker-deployment)
5. [Kubernetes Deployment](#kubernetes-deployment)
6. [Monitoring](#monitoring)
7. [Scaling](#scaling)
8. [Backup and Recovery](#backup-and-recovery)

## Prerequisites

### Hardware Requirements

| Component      | Minimum | Recommended |
|----------------|---------|-------------|
| CPU            | 2 cores | 4+ cores    |
| RAM            | 2GB     | 8GB+        |
| Storage        | 10GB    | 50GB+       |
| Network        | 100Mbps | 1Gbps+      |

### Software Requirements

- Python 3.8+
- pip (Python package manager)
- Docker (for containerized deployment)
- Kubernetes (for orchestrated deployment)
- Redis (for caching)
- PostgreSQL (for persistent storage)

## Installation

### Manual Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/atous-secure-network.git
   cd atous-secure-network
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Configuration

Create a `.env` file in the project root with the following variables:

```env
# Node Configuration
NODE_ID=node1
NODE_ROLE=coordinator  # or 'worker'

# Model Configuration
MODEL_PATH=./models/current_model.bin
STORAGE_PATH=./storage
MAX_VERSIONS=5

# Network Configuration
LISTEN_HOST=0.0.0.0
LISTEN_PORT=8000
BOOTSTRAP_NODES=node1.example.com:8000,node2.example.com:8000

# Security Configuration
ENABLE_ENCRYPTION=true
ENABLE_AUTH=true
AUTH_TOKEN=your-secure-token

# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_NAME=atous_network
DB_USER=postgres
DB_PASSWORD=your-secure-password

# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0
```

## Docker Deployment

1. Prepare environment:
   - Copy `deploy/.env.example` to `.env` and adjust values (hosts, CORS, admin keys):
   ```bash
   cp deploy/.env.example .env
   ```

2. Build the Docker image:
   ```bash
   docker build -t atous-network .
   ```

3. Run a container (standalone):
   ```bash
   docker run -d \
     --name atous-node \
     -p 8000:8000 \
     --env-file .env \
     -v ./logs:/app/logs \
     atous-network
   ```

4. Using docker-compose with Nginx reverse proxy:
   ```bash
   docker compose up -d --build
   ```
   - App available at http://localhost via Nginx → FastAPI (app listens on 8000)
   - Adjust `deploy/nginx/nginx.conf` for TLS in production (recommend terminating TLS at Nginx)

### Windows PowerShell tips

- Do not chain env sets with `&&`. Use `$env:VAR='value'` before the command.
- Use `curl.exe` (not `curl`) to avoid alias issues.
- For JSON POST, prefer Python `requests` or the provided seed script to avoid quoting/escaping problems in PowerShell.

## Kubernetes Deployment

1. Create a namespace:
   ```bash
   kubectl create namespace atous-network
   ```

2. Create a secret for environment variables:
   ```bash
   kubectl create secret generic atous-secrets --from-env-file=.env -n atous-network
   ```

3. Deploy the application:
   ```bash
   kubectl apply -f k8s/deployment.yaml
   kubectl apply -f k8s/service.yaml
   kubectl apply -f k8s/ingress.yaml
   ```

## Monitoring

### Metrics Collection

The application exposes Prometheus metrics at `/metrics`.

1. Deploy Prometheus and Grafana:
   ```bash
   helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
   helm install prometheus prometheus-community/kube-prometheus-stack -n monitoring
   ```

2. Configure Prometheus to scrape metrics:
   ```yaml
   # prometheus-values.yaml
   prometheus:
     prometheusSpec:
       additionalScrapeConfigs:
         - job_name: 'atous-network'
           static_configs:
             - targets: ['atous-service:8000']
   ```

### Logging

Use Fluent Bit for log collection:

```yaml
# fluent-bit-values.yaml
config:
  inputs: |
    [INPUT]
        Name              tail
        Tag               atous.*
        Path              /var/log/atous/*.log
        Parser            docker
        Refresh_Interval  5
```

## Scaling

### Horizontal Scaling

For high availability, deploy multiple instances behind a load balancer:

```yaml
# k8s/hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: atous-network
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: atous-network
  minReplicas: 3
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
```

## Backup and Recovery

### Data Backup

1. Schedule regular backups of the storage directory:
   ```bash
   # Example backup script
   TIMESTAMP=$(date +%Y%m%d%H%M%S)
   BACKUP_DIR=/backups/atous-network/$TIMESTAMP
   mkdir -p $BACKUP_DIR
   
   # Backup models and storage
   cp -r /path/to/atous-network/storage $BACKUP_DIR/
   cp -r /path/to/atous-network/models $BACKUP_DIR/
   
   # Dump database
   pg_dump -h $DB_HOST -U $DB_USER $DB_NAME > $BACKUP_DIR/db_dump.sql
   
   # Upload to cloud storage
   # aws s3 cp --recursive $BACKUP_DIR s3://your-bucket/backups/$TIMESTAMP/
   ```

### Disaster Recovery

1. Restore from backup:
   ```bash
   # Restore database
   psql -h $DB_HOST -U $DB_USER $DB_NAME < /path/to/backup/db_dump.sql
   
   # Restore files
   cp -r /path/to/backup/storage/* /path/to/atous-network/storage/
   cp -r /path/to/backup/models/* /path/to/atous-network/models/
   ```

## Security Considerations

### Network Security

- Use TLS for all network communications
- Implement network policies to restrict access
- Use private networks for node-to-node communication

### Secrets Management

- Store sensitive information in Kubernetes secrets or a dedicated secrets manager
- Rotate API keys and tokens regularly
- Use RBAC to control access to sensitive resources

### Updates

- Regularly update dependencies
- Apply security patches promptly
- Test updates in a staging environment before production deployment
