# ZHTP Complete System Deployment Guide

This directory contains everything needed to deploy and test the complete ZHTP blockchain internet system using Docker containers.

## 🚀 Quick Start

### Prerequisites
- Docker 20.10+
- Docker Compose 2.0+
- 8GB+ RAM available
- 20GB+ disk space

### One-Command Deployment

**Linux/macOS:**
```bash
./deploy-complete-system.sh
```

**Windows:**
```cmd
deploy-complete-system.bat
```

This will:
1. Build all Docker images
2. Deploy the complete infrastructure
3. Run the trusted setup ceremony
4. Register validators
5. Start the blockchain
6. Run comprehensive tests
7. Display system status

## 📋 System Components

### Core Infrastructure
- **Ceremony Coordinator**: Orchestrates the trusted setup ceremony
- **Ceremony Participants** (3): Contribute to the multi-party computation
- **Primary Validator**: Main consensus participant with auto-registration
- **Secondary Validator**: Backup consensus participant
- **Storage Node**: Decentralized content storage
- **Full Node**: Bootstrap and relay node

### Testing & Monitoring
- **Test Runner**: Comprehensive end-to-end testing
- **Grafana Dashboard**: System monitoring and metrics
- **Prometheus**: Metrics collection
- **Loki**: Log aggregation

## 🔧 Advanced Usage

### Individual Commands

**Build only:**
```bash
./deploy-complete-system.sh build
```

**Deploy without testing:**
```bash
./deploy-complete-system.sh deploy
```

**Run tests only:**
```bash
./deploy-complete-system.sh test
```

**Show system status:**
```bash
./deploy-complete-system.sh status
```

**Cleanup everything:**
```bash
./deploy-complete-system.sh clean
```

### Interactive Mode
```bash
./deploy-complete-system.sh --interactive
```

Available interactive commands:
- `status` - Show system status
- `test` - Run tests again
- `logs` - Show recent logs
- `stop` - Stop all services
- `restart` - Restart all services
- `quit` - Exit interactive mode

## 🌐 Service URLs

Once deployed, access services at:

- **Ceremony Coordinator**: http://localhost:8080
- **Primary Validator**: http://localhost:8090
- **Secondary Validator**: http://localhost:8091  
- **Storage Node**: http://localhost:8092
- **Full Node**: http://localhost:8093
- **Monitoring Dashboard**: http://localhost:3000 (admin/zhtp123)
- **Metrics**: http://localhost:9090

## 🧪 Testing

The system includes comprehensive testing:

### Automated Tests
- **Ceremony Completion**: Verifies trusted setup ceremony
- **Validator Registration**: Confirms validator auto-registration
- **Blockchain Operation**: Tests block production and finality
- **ZK Proof System**: Validates zero-knowledge proof generation
- **Storage Operations**: Tests decentralized storage
- **Network Connectivity**: Verifies peer-to-peer networking
- **Quantum Cryptography**: Tests post-quantum algorithms
- **End-to-End Transactions**: Complete transaction flow with ZK proofs
- **DAO Voting**: Anonymous voting with zero-knowledge proofs
- **DNS Resolution**: Decentralized DNS with ownership proofs

### Manual Testing
```bash
# Run specific test
docker-compose -f docker-compose.full-test.yml --profile test run --rm zhtp-test-runner ./test-scripts/test-e2e-transaction.sh

# View test results
cat data/test-results/test-report.json

# Check container logs
docker-compose -f docker-compose.full-test.yml logs zhtp-validator-primary
```

## 📊 Monitoring

### Grafana Dashboard
- URL: http://localhost:3000
- Username: admin
- Password: zhtp123

Pre-configured dashboards for:
- Blockchain metrics (block height, transaction rate)
- Network health (peer count, connectivity)
- Ceremony progress and validation
- System performance (CPU, memory, disk)

### Prometheus Metrics
- URL: http://localhost:9090
- Scrapes metrics from all ZHTP nodes
- Custom ZHTP-specific metrics available

### Log Aggregation
- Loki collects logs from all containers
- Accessible through Grafana
- Real-time log streaming and search

## 🔒 Security Features Tested

- **Post-Quantum Cryptography**: Dilithium 5, Kyber, BLAKE3
- **Zero-Knowledge Proofs**: KZG commitments, PLONK/SNARK circuits
- **Trusted Setup**: Multi-party ceremony with verification
- **Anonymous Transactions**: Privacy-preserving transfers
- **Quantum-Resistant Signatures**: All communications secured

## 🏗️ Architecture

### Container Network
All services run on isolated Docker network (172.20.0.0/16) with:
- Service discovery via container names
- Health checks and dependencies
- Persistent volumes for data/logs
- Automatic restart policies

### Data Persistence
- `ceremony-params/`: Shared trusted setup parameters
- `data/`: Node-specific blockchain data
- `logs/`: Service logs
- `test-results/`: Test outputs and reports

### Resource Allocation
- **Ceremony services**: 512MB RAM each
- **Validator nodes**: 1GB RAM each  
- **Storage node**: 2GB RAM + 10GB storage
- **Monitoring**: 1GB RAM total

## 🔧 Configuration

### Node Configuration
Each node type has specific configuration in `docker-config/`:
- `ceremony.json`: Ceremony participant settings
- `validator.json`: Validator node settings
- `storage.json`: Storage node settings
- `full.json`: Full node settings

### Environment Variables
Key environment variables:
- `ZHTP_NODE_TYPE`: Node type (ceremony, validator, storage, full)
- `ZHTP_NETWORK_ID`: Network identifier (zhtp-testnet)
- `ZHTP_AUTO_REGISTER`: Enable validator auto-registration
- `RUST_LOG`: Logging level (debug, info, warn, error)

## 🐛 Troubleshooting

### Common Issues

**Docker not running:**
```bash
sudo systemctl start docker  # Linux
# or start Docker Desktop on Windows/macOS
```

**Port conflicts:**
- Check if ports 8080-8093, 3000, 9090 are free
- Modify `docker-compose.full-test.yml` to use different ports

**Insufficient resources:**
- Ensure 8GB+ RAM available
- Close other applications
- Consider reducing number of ceremony participants

**Ceremony timeout:**
- Ceremony may take 5-10 minutes
- Check ceremony coordinator logs:
```bash
docker-compose -f docker-compose.full-test.yml logs zhtp-ceremony-coordinator
```

**Tests failing:**
- Ensure all services are healthy first
- Run tests individually to isolate issues
- Check test-specific logs in `data/test-results/`

### Debugging Commands

```bash
# Check service health
docker-compose -f docker-compose.full-test.yml ps

# View specific service logs
docker-compose -f docker-compose.full-test.yml logs -f [service-name]

# Execute commands in running container
docker-compose -f docker-compose.full-test.yml exec zhtp-validator-primary /bin/bash

# Check ceremony status
curl http://localhost:8080/ceremony/status

# Check validator registration  
curl http://localhost:8090/validators/list

# Check blockchain height
curl http://localhost:8090/blockchain/height
```

## 📚 Additional Resources

- [ZHTP Documentation](../docs/)
- [Security Audit Reports](../FINAL_PRODUCTION_READY_AUDIT.md)
- [Circuit Verification](../FINAL_CIRCUIT_VERIFICATION_REPORT.md)
- [Ceremony Participation Guide](../docs/ceremony-participation-guide.md)

## 🤝 Support

For issues or questions:
1. Check logs in deployment directory
2. Review troubleshooting section above
3. Examine test results in `data/test-results/`
4. Use `status` command to verify system state

The deployment creates a complete, production-ready ZHTP blockchain internet system with all cryptographic components, zero-knowledge proofs, and quantum-resistant security features fully operational and tested.
