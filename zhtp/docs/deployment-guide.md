# ZHTP Deployment Guide

## Overview

This guide covers deployment strategies, installation procedures, and operational considerations for ZHTP node orchestrator across various environments and use cases.

## System Requirements

### Minimum Requirements
- **CPU**: 2 cores, 2.0 GHz
- **RAM**: 4 GB
- **Storage**: 50 GB available space
- **Network**: Broadband internet connection (for hybrid mode)
- **OS**: Linux (Ubuntu 20.04+), Windows 10+, macOS 12+

### Recommended Requirements
- **CPU**: 4+ cores, 3.0 GHz
- **RAM**: 8+ GB
- **Storage**: 200+ GB SSD
- **Network**: High-speed internet or dense mesh coverage
- **OS**: Linux server distribution

### Hardware-Specific Requirements

#### Pure Mesh Mode
- **Network Interfaces**: Wi-Fi, Bluetooth, or dedicated mesh radio
- **Range**: Sufficient peer density within communication range
- **Power**: Stable power supply for continuous operation

#### Validator Nodes
- **CPU**: 8+ cores, high-frequency
- **RAM**: 16+ GB
- **Storage**: 1+ TB NVMe SSD
- **Network**: Low-latency, high-bandwidth connection
- **Uptime**: 99.9%+ availability requirement

#### Storage Nodes
- **Storage**: 1+ TB available space per node
- **I/O**: High IOPS for storage operations
- **Bandwidth**: High bandwidth for data transfers
- **Redundancy**: RAID configuration recommended

## Installation Methods

### Cargo Installation (Recommended)
```bash
# Install Rust and Cargo
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Clone and build ZHTP
git clone https://github.com/zhtp/zhtp
cd zhtp
cargo build --release

# Install binary
sudo cp target/release/zhtp /usr/local/bin/
```

### Binary Installation
```bash
# Download latest release
wget https://github.com/zhtp/zhtp/releases/latest/download/zhtp-linux-x64.tar.gz
tar -xzf zhtp-linux-x64.tar.gz

# Install
sudo mv zhtp /usr/local/bin/
sudo chmod +x /usr/local/bin/zhtp
```

### Docker Installation
```bash
# Pull Docker image
docker pull zhtp/node:latest

# Run container
docker run -d \
  --name zhtp-node \
  -p 9333:9333 \
  -p 33444:33444 \
  -v /var/lib/zhtp:/data \
  zhtp/node:latest
```

### Package Manager Installation
```bash
# Ubuntu/Debian
wget -qO - https://packages.zhtp.network/key.gpg | sudo apt-key add -
echo "deb https://packages.zhtp.network/ubuntu focal main" | sudo tee /etc/apt/sources.list.d/zhtp.list
sudo apt update
sudo apt install zhtp-node

# CentOS/RHEL
sudo yum install -y yum-utils
sudo yum-config-manager --add-repo https://packages.zhtp.network/centos/zhtp.repo
sudo yum install zhtp-node
```

## Pre-Installation Setup

### User and Directory Setup
```bash
# Create ZHTP user
sudo useradd -r -s /bin/false zhtp

# Create data directories
sudo mkdir -p /var/lib/zhtp
sudo mkdir -p /etc/zhtp
sudo mkdir -p /var/log/zhtp

# Set permissions
sudo chown -R zhtp:zhtp /var/lib/zhtp
sudo chown -R zhtp:zhtp /var/log/zhtp
sudo chmod 750 /var/lib/zhtp
sudo chmod 755 /etc/zhtp
```

### Network Configuration
```bash
# Configure firewall (Ubuntu/Debian)
sudo ufw allow 9333/tcp   # API port
sudo ufw allow 33444/tcp  # Mesh port
sudo ufw allow 33444/udp  # Mesh UDP
sudo ufw enable

# Configure firewall (CentOS/RHEL)
sudo firewall-cmd --permanent --add-port=9333/tcp
sudo firewall-cmd --permanent --add-port=33444/tcp
sudo firewall-cmd --permanent --add-port=33444/udp
sudo firewall-cmd --reload
```

### System Dependencies
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev

# CentOS/RHEL
sudo yum groupinstall -y "Development Tools"
sudo yum install -y openssl-devel pkgconfig

# macOS
brew install openssl pkg-config
```

## Deployment Configurations

### Development Deployment
Quick setup for development and testing.

#### Configuration File
Create `/etc/zhtp/dev-node.toml`:
```toml
[node]
log_level = "debug"
data_dir = "/var/lib/zhtp/dev"

[network]
mesh_port = 33445
pure_mesh = false

[api]
server_port = 9334
bind_address = "127.0.0.1"
enable_cors = true

[security]
security_level = "medium"

[monitoring]
enable_metrics = true
dashboard_port = 8082
```

#### Service Configuration
Create `/etc/systemd/system/zhtp-dev.service`:
```ini
[Unit]
Description=ZHTP Development Node
After=network.target

[Service]
Type=simple
User=zhtp
Group=zhtp
ExecStart=/usr/local/bin/zhtp node start --config /etc/zhtp/dev-node.toml
Restart=always
RestartSec=10
Environment=ZHTP_LOG_LEVEL=debug

[Install]
WantedBy=multi-user.target
```

#### Deployment Commands
```bash
# Enable and start service
sudo systemctl enable zhtp-dev
sudo systemctl start zhtp-dev

# Check status
sudo systemctl status zhtp-dev
zhtp --server 127.0.0.1:9334 node status
```

### Production Deployment
Enterprise-grade production deployment.

#### Configuration File
Create `/etc/zhtp/prod-node.toml`:
```toml
[node]
node_id = "prod-node-001"
log_level = "info"
data_dir = "/var/lib/zhtp/prod"

[network]
mesh_port = 33444
pure_mesh = false
bootstrap_peers = [
    "bootstrap1.zhtp.network:33444",
    "bootstrap2.zhtp.network:33444",
    "bootstrap3.zhtp.network:33444"
]

[api]
server_port = 9333
bind_address = "0.0.0.0"
enable_cors = false
max_connections = 5000

[security]
security_level = "maximum"
enable_encryption = true
key_rotation_interval = 43200

[blockchain]
enable_contracts = true
wasm_runtime = true
validator_mode = false

[storage]
max_storage_size = 107374182400  # 100GB
enable_compression = true
enable_encryption = true

[monitoring]
enable_metrics = true
dashboard_port = 8081
prometheus_export = true
prometheus_port = 9090

[logging]
level = "info"
format = "json"
file_rotation = true
output = "both"

[logging.file]
path = "/var/log/zhtp/node.log"
max_size = "100MB"
max_files = 10
```

#### Service Configuration
Create `/etc/systemd/system/zhtp-prod.service`:
```ini
[Unit]
Description=ZHTP Production Node
After=network.target
Wants=network.target

[Service]
Type=simple
User=zhtp
Group=zhtp
ExecStart=/usr/local/bin/zhtp node start --config /etc/zhtp/prod-node.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=10
LimitNOFILE=65536

# Security settings
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/zhtp /var/log/zhtp

# Environment
Environment=ZHTP_ENVIRONMENT=production
Environment=ZHTP_LOG_LEVEL=info

[Install]
WantedBy=multi-user.target
```

#### Deployment Commands
```bash
# Enable and start service
sudo systemctl enable zhtp-prod
sudo systemctl start zhtp-prod

# Check status and logs
sudo systemctl status zhtp-prod
sudo journalctl -u zhtp-prod -f
zhtp node status
```

### Pure Mesh Deployment
Complete ISP replacement deployment.

#### Network Isolation Setup
```bash
# Create isolation script
sudo tee /etc/zhtp/apply-isolation.sh << 'EOF'
#!/bin/bash
# Block TCP/IP traffic except mesh protocols
iptables -F
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow mesh protocol (custom port)
iptables -A INPUT -p udp --dport 33444 -j ACCEPT
iptables -A OUTPUT -p udp --sport 33444 -j ACCEPT

# Allow established connections for mesh
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

echo "Network isolation applied for pure mesh mode"
EOF

sudo chmod +x /etc/zhtp/apply-isolation.sh
```

#### Configuration File
Create `/etc/zhtp/pure-mesh.toml`:
```toml
[node]
log_level = "info"
data_dir = "/var/lib/zhtp/mesh"

[network]
mesh_port = 33444
pure_mesh = true
hybrid_mode = false

[mesh]
mode = "pure"
isolation_level = "complete"
tcp_ip_fallback = false

[network_isolation]
block_tcp_ip = true
mesh_only = true
auto_apply = true

[api]
server_port = 9333
bind_address = "mesh://0.0.0.0"  # Mesh-only API

[security]
security_level = "maximum"
```

#### Service Configuration
```ini
[Unit]
Description=ZHTP Pure Mesh Node
After=network.target

[Service]
Type=simple
User=zhtp
Group=zhtp
ExecStartPre=/etc/zhtp/apply-isolation.sh
ExecStart=/usr/local/bin/zhtp node start --config /etc/zhtp/pure-mesh.toml --pure-mesh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### High Availability Deployment
Multi-node cluster configuration.

#### Load Balancer Configuration (HAProxy)
Create `/etc/haproxy/haproxy.cfg`:
```
global
    daemon

defaults
    mode http
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms

frontend zhtp_frontend
    bind *:9333
    default_backend zhtp_nodes

backend zhtp_nodes
    balance roundrobin
    option httpchk GET /api/v1/health
    server node1 10.0.1.10:9333 check
    server node2 10.0.1.11:9333 check
    server node3 10.0.1.12:9333 check
```

#### Node Configuration
Each node gets a unique configuration:
```toml
[node]
node_id = "ha-node-001"  # Unique per node
data_dir = "/var/lib/zhtp/ha"

[network]
mesh_port = 33444
bootstrap_peers = [
    "10.0.1.10:33444",
    "10.0.1.11:33444", 
    "10.0.1.12:33444"
]

[api]
server_port = 9333
bind_address = "0.0.0.0"

[blockchain]
validator_mode = true
cluster_mode = true
peer_nodes = ["10.0.1.10", "10.0.1.11", "10.0.1.12"]
```

## Docker Deployment

### Docker Compose Configuration
Create `docker-compose.yml`:
```yaml
version: '3.8'

services:
  zhtp-node:
    image: zhtp/node:latest
    ports:
      - "9333:9333"
      - "33444:33444/tcp"
      - "33444:33444/udp"
    volumes:
      - zhtp-data:/data
      - ./config:/config:ro
    environment:
      - ZHTP_CONFIG=/config/node.toml
      - ZHTP_LOG_LEVEL=info
    restart: unless-stopped
    networks:
      - zhtp-network

  zhtp-dashboard:
    image: zhtp/dashboard:latest
    ports:
      - "8081:8081"
    depends_on:
      - zhtp-node
    environment:
      - ZHTP_NODE_URL=http://zhtp-node:9333
    networks:
      - zhtp-network

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus-data:/prometheus
    networks:
      - zhtp-network

volumes:
  zhtp-data:
  prometheus-data:

networks:
  zhtp-network:
    driver: bridge
```

### Kubernetes Deployment
Create Kubernetes manifests:

#### Namespace
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: zhtp
```

#### ConfigMap
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: zhtp-config
  namespace: zhtp
data:
  node.toml: |
    [node]
    log_level = "info"
    data_dir = "/data"
    
    [network]
    mesh_port = 33444
    
    [api]
    server_port = 9333
    bind_address = "0.0.0.0"
```

#### Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: zhtp-node
  namespace: zhtp
spec:
  replicas: 3
  selector:
    matchLabels:
      app: zhtp-node
  template:
    metadata:
      labels:
        app: zhtp-node
    spec:
      containers:
      - name: zhtp-node
        image: zhtp/node:latest
        ports:
        - containerPort: 9333
        - containerPort: 33444
        volumeMounts:
        - name: config
          mountPath: /config
        - name: data
          mountPath: /data
        env:
        - name: ZHTP_CONFIG
          value: /config/node.toml
      volumes:
      - name: config
        configMap:
          name: zhtp-config
      - name: data
        persistentVolumeClaim:
          claimName: zhtp-data
```

#### Service
```yaml
apiVersion: v1
kind: Service
metadata:
  name: zhtp-service
  namespace: zhtp
spec:
  selector:
    app: zhtp-node
  ports:
  - name: api
    port: 9333
    targetPort: 9333
  - name: mesh
    port: 33444
    targetPort: 33444
  type: LoadBalancer
```

## Cloud Deployment

### AWS Deployment
#### EC2 Instance Setup
```bash
# Launch EC2 instance
aws ec2 run-instances \
  --image-id ami-0c55b159cbfafe1d0 \
  --instance-type t3.medium \
  --key-name zhtp-key \
  --security-groups zhtp-sg \
  --user-data file://install-zhtp.sh

# Security group configuration
aws ec2 create-security-group \
  --group-name zhtp-sg \
  --description "ZHTP Node Security Group"

aws ec2 authorize-security-group-ingress \
  --group-name zhtp-sg \
  --protocol tcp \
  --port 9333 \
  --cidr 0.0.0.0/0

aws ec2 authorize-security-group-ingress \
  --group-name zhtp-sg \
  --protocol tcp \
  --port 33444 \
  --cidr 0.0.0.0/0
```

#### CloudFormation Template
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  ZhtpInstance:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ami-0c55b159cbfafe1d0
      InstanceType: t3.medium
      KeyName: !Ref KeyPairName
      SecurityGroups:
        - !Ref ZhtpSecurityGroup
      UserData:
        Fn::Base64: !Sub |
          #!/bin/bash
          curl -sSL https://install.zhtp.network | bash
          systemctl enable zhtp-prod
          systemctl start zhtp-prod

  ZhtpSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Security group for ZHTP node
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 9333
          ToPort: 9333
          CidrIp: 0.0.0.0/0
        - IpProtocol: tcp
          FromPort: 33444
          ToPort: 33444
          CidrIp: 0.0.0.0/0
```

### Google Cloud Platform
```bash
# Create VM instance
gcloud compute instances create zhtp-node \
  --image-family=ubuntu-2004-lts \
  --image-project=ubuntu-os-cloud \
  --machine-type=n1-standard-2 \
  --tags=zhtp-node \
  --metadata-from-file startup-script=install-zhtp.sh

# Create firewall rules
gcloud compute firewall-rules create allow-zhtp-api \
  --allow tcp:9333 \
  --target-tags zhtp-node

gcloud compute firewall-rules create allow-zhtp-mesh \
  --allow tcp:33444,udp:33444 \
  --target-tags zhtp-node
```

### Azure Deployment
```bash
# Create resource group
az group create --name zhtp-rg --location eastus

# Create VM
az vm create \
  --resource-group zhtp-rg \
  --name zhtp-node \
  --image UbuntuLTS \
  --size Standard_B2s \
  --admin-username azureuser \
  --ssh-key-values ~/.ssh/id_rsa.pub \
  --custom-data install-zhtp.sh

# Open ports
az vm open-port --port 9333 --resource-group zhtp-rg --name zhtp-node
az vm open-port --port 33444 --resource-group zhtp-rg --name zhtp-node
```

## Monitoring and Logging

### Prometheus Configuration
Create `/etc/prometheus/prometheus.yml`:
```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'zhtp-nodes'
    static_configs:
      - targets: 
        - 'localhost:9090'
        - 'node1.zhtp.local:9090'
        - 'node2.zhtp.local:9090'
    metrics_path: '/api/v1/metrics'
```

### Grafana Dashboard
Import dashboard configuration for ZHTP metrics visualization.

### Log Aggregation (ELK Stack)
```yaml
# Logstash configuration for ZHTP logs
input {
  file {
    path => "/var/log/zhtp/*.log"
    type => "zhtp-log"
  }
}

filter {
  if [type] == "zhtp-log" {
    json {
      source => "message"
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "zhtp-logs-%{+YYYY.MM.dd}"
  }
}
```

## Backup and Recovery

### Data Backup Strategy
```bash
# Create backup script
#!/bin/bash
BACKUP_DIR="/backup/zhtp/$(date +%Y%m%d)"
mkdir -p $BACKUP_DIR

# Backup data directory
tar -czf $BACKUP_DIR/zhtp-data.tar.gz /var/lib/zhtp/

# Backup configuration
cp -r /etc/zhtp/ $BACKUP_DIR/config/

# Backup logs
tar -czf $BACKUP_DIR/zhtp-logs.tar.gz /var/log/zhtp/

echo "Backup completed: $BACKUP_DIR"
```

### Automated Backup (Cron)
```bash
# Add to crontab
0 2 * * * /usr/local/bin/backup-zhtp.sh
```

### Recovery Procedure
```bash
# Stop ZHTP service
sudo systemctl stop zhtp-prod

# Restore data
sudo rm -rf /var/lib/zhtp/*
sudo tar -xzf backup/zhtp-data.tar.gz -C /

# Restore configuration
sudo cp -r backup/config/* /etc/zhtp/

# Fix permissions
sudo chown -R zhtp:zhtp /var/lib/zhtp

# Start service
sudo systemctl start zhtp-prod
```

## Maintenance and Updates

### Update Procedure
```bash
# Download new version
wget https://github.com/zhtp/zhtp/releases/latest/download/zhtp-linux-x64.tar.gz

# Backup current installation
sudo cp /usr/local/bin/zhtp /usr/local/bin/zhtp.backup

# Stop service
sudo systemctl stop zhtp-prod

# Update binary
sudo tar -xzf zhtp-linux-x64.tar.gz
sudo mv zhtp /usr/local/bin/
sudo chmod +x /usr/local/bin/zhtp

# Start service
sudo systemctl start zhtp-prod

# Verify update
zhtp --version
zhtp node status
```

### Health Checks
```bash
# Regular health monitoring script
#!/bin/bash
if ! systemctl is-active --quiet zhtp-prod; then
    echo "ZHTP service is not running"
    systemctl restart zhtp-prod
    exit 1
fi

if ! zhtp node status > /dev/null 2>&1; then
    echo "ZHTP node is not responding"
    systemctl restart zhtp-prod
    exit 1
fi

echo "ZHTP node is healthy"
```

## Troubleshooting

### Common Issues

#### Service Won't Start
```bash
# Check logs
sudo journalctl -u zhtp-prod -f

# Check configuration
zhtp config validate --config /etc/zhtp/prod-node.toml

# Check permissions
sudo chown -R zhtp:zhtp /var/lib/zhtp
```

#### Network Connectivity Issues
```bash
# Test mesh connectivity
zhtp network test

# Check firewall
sudo ufw status
sudo iptables -L

# Verify ports
sudo netstat -tlnp | grep 33444
sudo netstat -tlnp | grep 9333
```

#### Performance Issues
```bash
# Check system resources
htop
df -h
iostat -x 1

# Monitor ZHTP metrics
zhtp monitor system
zhtp monitor performance
```

This deployment guide provides comprehensive instructions for deploying ZHTP nodes across various environments, from development setups to enterprise production clusters with high availability and monitoring.