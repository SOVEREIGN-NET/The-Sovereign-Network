# PoUW Production Checklist

Pre-deployment checklist for the Proof-of-Useful-Work subsystem.

## Infrastructure Requirements

### Hardware
- [ ] Minimum 4 CPU cores (8+ recommended for high throughput)
- [ ] Minimum 8GB RAM (16GB+ recommended)
- [ ] SSD storage with at least 100GB free space
- [ ] Network: 1Gbps minimum

### Software
- [ ] Rust 1.87+ installed
- [ ] PostgreSQL 15+ or compatible database
- [ ] Redis for session/nonce caching (optional but recommended)
- [ ] Prometheus + Grafana for monitoring

## Security Configuration

### TLS/SSL
- [ ] Valid TLS certificate installed
- [ ] TLS 1.3 enforced
- [ ] Certificate auto-renewal configured
- [ ] HSTS headers enabled

### Authentication
- [ ] Node signing key generated securely
- [ ] Key stored in secure keystore (HSM recommended)
- [ ] Key rotation procedure documented

### Rate Limiting
- [ ] Per-IP limits configured (default: 100 req/min)
- [ ] Per-DID limits configured (default: 50 req/min)
- [ ] Batch size limits configured (default: 100 receipts)
- [ ] Request timeout configured (default: 30s)

### Secrets
- [ ] All secrets in environment variables or secret manager
- [ ] No secrets in config files or code
- [ ] Secrets rotation procedure documented

## Application Configuration

### Environment Variables
```bash
# Required
POUW_NODE_SECRET_KEY=<base64-encoded-secret-key>
POUW_DATABASE_URL=postgres://user:pass@host:5432/pouw
POUW_METRICS_PORT=9090

# Optional
POUW_RATE_LIMIT_IP=100
POUW_RATE_LIMIT_DID=50
POUW_BATCH_SIZE_MAX=100
POUW_CHALLENGE_TTL_SECS=300
POUW_LOG_LEVEL=info
```

### Feature Flags
- [ ] `production` feature enabled
- [ ] `development` feature disabled
- [ ] Debug logging disabled

## Database Setup

### Migrations
- [ ] All migrations applied
- [ ] Schema validated
- [ ] Indexes created for:
  - `challenges.task_id`
  - `challenges.expires_at`
  - `receipts.client_did`
  - `receipts.submitted_at`
  - `rewards.epoch`
  - `nonces.nonce` (unique)

### Backup
- [ ] Automated backup configured
- [ ] Point-in-time recovery tested
- [ ] Backup retention policy defined (30 days minimum)

## Monitoring Setup

### Prometheus Metrics
- [ ] Metrics endpoint exposed (`/metrics`)
- [ ] Prometheus scraping configured
- [ ] Recording rules for aggregation

### Alerts
| Alert | Condition | Severity |
|-------|-----------|----------|
| High rejection rate | > 10% for 5 min | Warning |
| Very high rejection rate | > 50% for 5 min | Critical |
| Rate limit storm | > 100 denials/min | Warning |
| Signature verification slow | P99 > 100ms | Warning |
| Service unhealthy | health check fails | Critical |
| Database connection lost | connection errors | Critical |

### Dashboards
- [ ] Overview dashboard created
- [ ] Throughput graphs
- [ ] Latency histograms
- [ ] Error rate tracking
- [ ] Dispute tracking

## Load Testing

### Pre-deployment Tests
- [ ] Challenge endpoint: 1000 concurrent requests
- [ ] Submit endpoint: 1000 receipts/second sustained
- [ ] Peak load test: 5x expected traffic
- [ ] Soak test: 24 hours at expected load

### Performance Baselines
| Metric | Target | Measured |
|--------|--------|----------|
| Challenge latency P50 | < 10ms | ___ |
| Challenge latency P99 | < 100ms | ___ |
| Submit latency P50 | < 50ms | ___ |
| Submit latency P99 | < 500ms | ___ |
| Throughput | > 1000 rps | ___ |

## Deployment

### Pre-deployment
- [ ] Code reviewed and approved
- [ ] All tests passing
- [ ] SonarCloud analysis passed
- [ ] Security scan completed
- [ ] Documentation updated

### Deployment Steps
1. [ ] Enable maintenance mode (if applicable)
2. [ ] Backup current state
3. [ ] Deploy new version
4. [ ] Run smoke tests
5. [ ] Verify metrics collection
6. [ ] Disable maintenance mode
7. [ ] Monitor for 30 minutes

### Rollback Plan
- [ ] Previous version tagged and available
- [ ] Rollback command documented
- [ ] Rollback tested in staging

## Post-deployment

### Verification
- [ ] Health endpoint returning 200
- [ ] Metrics being collected
- [ ] Challenge endpoint responding
- [ ] Submit endpoint responding
- [ ] Logs showing expected activity

### Communication
- [ ] Status page updated
- [ ] Team notified
- [ ] Monitoring dashboard shared

## Operational Procedures

### On-call
- [ ] On-call rotation defined
- [ ] Escalation path documented
- [ ] Contact information current

### Runbook References
- [RUNBOOK.md](./RUNBOOK.md) - Operational procedures
- [THREAT_MODEL.md](./THREAT_MODEL.md) - Security considerations
- [FAILOVER_SCENARIOS.md](./FAILOVER_SCENARIOS.md) - Failure handling

## Sign-off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Development Lead | | | |
| Security Review | | | |
| Operations | | | |
| Product Owner | | | |
