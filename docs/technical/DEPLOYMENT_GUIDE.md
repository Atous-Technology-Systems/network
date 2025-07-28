# ATous Secure Network - Deployment Guide

## Deployment Overview

This guide covers the deployment process for ATous Secure Network, including system requirements, installation steps, configuration, and maintenance procedures.

## System Requirements

### Hardware Requirements

#### Minimum Specifications
- CPU: 2 cores, 2.0 GHz
- RAM: 4 GB
- Storage: 20 GB
- Network: 100 Mbps Ethernet

#### Recommended Specifications
- CPU: 4+ cores, 3.0+ GHz
- RAM: 8+ GB
- Storage: 50+ GB SSD
- Network: 1 Gbps Ethernet

#### Optional Hardware
- Raspberry Pi (for LoRa hardware testing)
- LoRa modules (for physical deployment)
- GPIO interfaces (for hardware interaction)

### Software Requirements

#### Core Requirements
- Python 3.13+
- pip 23.0+
- virtualenv or venv
- Git

#### System Dependencies
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y \
    python3.13 \
    python3-pip \
    python3-venv \
    mosquitto \
    mosquitto-clients \
    build-essential \
    libssl-dev

# CentOS/RHEL
sudo yum install -y \
    python3.13 \
    python3-pip \
    mosquitto \
    mosquitto-clients \
    gcc \
    openssl-devel
```

## Installation

### 1. Environment Setup
```bash
# Clone repository
git clone https://github.com/devrodts/Atous-Sec-Network.git
cd Atous-Sec-Network

# Create virtual environment
python -m venv venv

# Activate environment
# On Linux/Mac:
source venv/bin/activate
# On Windows:
.\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. System Configuration

#### Basic Configuration
Create a `config.yaml` file in the project root:
```yaml
security:
  abiss:
    threshold: 0.85
    learning_rate: 0.01
    update_interval: 300
  
  nnis:
    memory_size: 10000
    detection_threshold: 0.75
    response_timeout: 60

network:
  lora:
    region: "BR"
    spreading_factor: 7
    tx_power: 14
    bandwidth: 125000
  
  p2p:
    health_check_interval: 300
    recovery_timeout: 600
    consensus_quorum: 0.6

core:
  model_manager:
    storage_path: "/models"
    version_control: true
    auto_rollback: true
  
  llm:
    model_config:
      type: "transformers"
      name: "bert-base-multilingual-cased"
    cache_config:
      max_size: 1000
      ttl: 3600
```

#### Environment Variables
Create a `.env` file:
```env
# Security Settings
SECURITY_KEY=your-secure-key
ENCRYPTION_KEY=your-encryption-key

# Network Settings
MQTT_BROKER=localhost
MQTT_PORT=1883
MQTT_USER=your-user
MQTT_PASS=your-password

# Storage Settings
MODEL_STORAGE=/path/to/models
DATA_STORAGE=/path/to/data

# Logging
LOG_LEVEL=INFO
LOG_PATH=/path/to/logs
```

### 3. Service Setup

#### Systemd Service
Create `/etc/systemd/system/atous-network.service`:
```ini
[Unit]
Description=ATous Secure Network
After=network.target

[Service]
Type=simple
User=atous
Group=atous
WorkingDirectory=/opt/Atous-Sec-Network
Environment=PYTHONPATH=/opt/Atous-Sec-Network
ExecStart=/opt/Atous-Sec-Network/venv/bin/python -m atous_sec_network
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable and start the service:
```bash
sudo systemctl enable atous-network
sudo systemctl start atous-network
```

## Deployment Verification

### 1. System Check
```bash
# Check service status
sudo systemctl status atous-network

# Check logs
sudo journalctl -u atous-network

# Verify Python environment
source venv/bin/activate
python -c "import atous_sec_network; print('OK')"
```

### 2. Test Suite
```bash
# Run all tests
pytest tests/unit/ -v

# Run specific system tests
pytest tests/unit/test_abiss_system.py -v
pytest tests/unit/test_nnis_system.py -v
pytest tests/unit/test_lora_optimizer.py -v

# Run with coverage
pytest tests/unit/ --cov=atous_sec_network --cov-report=html
```

### 3. Health Checks
```bash
# Check MQTT broker
mosquitto_sub -t "atous/health" -C 1

# Verify P2P connections
curl http://localhost:8000/health

# Test LoRa communication
python scripts/test_lora.py
```

## Monitoring & Maintenance

### Log Management
```bash
# Configure log rotation
sudo nano /etc/logrotate.d/atous-network

/var/log/atous-network/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 atous atous
}
```

### Backup Procedures
```bash
# Backup configuration
sudo cp /opt/Atous-Sec-Network/config.yaml /backup/

# Backup model data
sudo rsync -av /path/to/models/ /backup/models/

# Backup databases
sudo pg_dump atous_db > /backup/atous_db.sql
```

### Update Procedures
```bash
# Stop service
sudo systemctl stop atous-network

# Backup current version
cp -r /opt/Atous-Sec-Network /opt/Atous-Sec-Network.bak

# Update code
cd /opt/Atous-Sec-Network
git pull origin master

# Update dependencies
source venv/bin/activate
pip install -r requirements.txt

# Run migrations
python scripts/migrate.py

# Start service
sudo systemctl start atous-network
```

## Troubleshooting

### Common Issues

#### Service Won't Start
1. Check logs: `journalctl -u atous-network -n 50`
2. Verify permissions: `ls -l /opt/Atous-Sec-Network`
3. Check Python environment: `source venv/bin/activate`
4. Verify config file: `python scripts/verify_config.py`

#### Network Connection Issues
1. Check MQTT broker: `systemctl status mosquitto`
2. Verify firewall rules: `sudo ufw status`
3. Test network connectivity: `ping mqtt.broker`
4. Check certificates: `ls -l /etc/atous/certs/`

#### Hardware Errors
1. Check LoRa module: `ls /dev/ttyUSB*`
2. Verify GPIO permissions: `groups atous`
3. Test hardware connection: `python scripts/test_hardware.py`
4. Check kernel modules: `lsmod | grep lora`

## Security Considerations

### Access Control
- Use strong passwords
- Implement role-based access
- Regular audit of access logs
- Proper file permissions

### Network Security
- Enable firewall rules
- Use TLS for MQTT
- Implement rate limiting
- Regular security scans

### Data Protection
- Encrypt sensitive data
- Regular backups
- Secure key management
- Access logging

## Support

### Getting Help
- Documentation: `/docs`
- Issue Tracker: GitHub Issues
- Community Forum: [Link]
- Email Support: support@atous.tech

### Reporting Issues
1. Check existing issues
2. Gather relevant logs
3. Create detailed report
4. Include environment info
