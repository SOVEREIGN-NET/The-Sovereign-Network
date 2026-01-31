# PoUW Operational Runbook

Operational procedures for the Proof-of-Useful-Work subsystem.

## Quick Reference

### Health Check Endpoints
- **Liveness**: `GET /health/live` - Returns 200 if process is running
- **Readiness**: `GET /health/ready` - Returns 200 if ready to accept traffic
- **Full Health**: `GET /health` - Returns detailed health status

### Key Metrics
- `pouw_receipts_received_total` - Total receipts received
- `pouw_receipts_rejected_total{reason="*"}` - Rejections by reason
- `pouw_rate_limit_denials_total` - Rate limit hits
- `pouw_challenges_issued_total` - Challenges issued

## Common Operations

### 1. Check Service Status

```bash
# Health check
curl -s http://localhost:8080/health | jq .

# Expected output for healthy service:
{
  "status": "healthy",
  "version": "1.0.0",
  "uptime_seconds": 12345,
  "components": [...]
}
```

### 2. View Current Metrics

```bash
# Prometheus metrics
curl -s http://localhost:9090/metrics | grep pouw_

# Key metrics to check:
# - pouw_receipts_received_total
# - pouw_receipts_rejected_total
# - pouw_rate_limit_denials_total
```

### 3. Check Logs

```bash
# Recent logs
journalctl -u pouw-node -n 100

# Error logs only
journalctl -u pouw-node -p err -n 50

# Follow logs
journalctl -u pouw-node -f
```

## Incident Response Procedures

### High Rejection Rate Alert

**Symptoms:**
- `pouw_receipts_rejected_total` increasing rapidly
- Alert: "Rejection rate > 10%"

**Diagnosis:**
1. Check rejection reasons:
   ```bash
   curl -s http://localhost:9090/metrics | grep pouw_receipts_rejected_total
   ```

2. Common causes by reason:
   - `invalid_signature`: Client key mismatch or corruption
   - `expired_challenge`: Clock drift or slow clients
   - `duplicate_nonce`: Replay attack or client bug
   - `malformed_receipt`: Protocol version mismatch

**Resolution:**
- `invalid_signature`: Verify client keys, check for updates
- `expired_challenge`: Increase TTL temporarily, check NTP sync
- `duplicate_nonce`: Investigate client, may be attack
- `malformed_receipt`: Check client version compatibility

### Rate Limit Storm Alert

**Symptoms:**
- `pouw_rate_limit_denials_total` spiking
- Legitimate users reporting errors

**Diagnosis:**
1. Check top offenders (requires log analysis):
   ```bash
   grep "rate limit exceeded" /var/log/pouw/*.log | \
     awk '{print $NF}' | sort | uniq -c | sort -rn | head -10
   ```

2. Determine if attack or legitimate traffic spike

**Resolution:**
- **If attack**: Block offending IPs at firewall level
- **If legitimate**: Temporarily increase limits or scale out

### Database Connection Issues

**Symptoms:**
- Health check shows database unhealthy
- Errors in logs: "connection refused" or "too many connections"

**Diagnosis:**
1. Check database status:
   ```bash
   psql -h $DB_HOST -U $DB_USER -c "SELECT 1"
   ```

2. Check connection count:
   ```bash
   psql -c "SELECT count(*) FROM pg_stat_activity WHERE datname='pouw'"
   ```

**Resolution:**
- **Connection refused**: Restart database, check network
- **Too many connections**: Increase pool size or max_connections
- **Slow queries**: Check for missing indexes, run VACUUM ANALYZE

### Service Crash

**Symptoms:**
- Health checks failing
- Service not responding

**Immediate Actions:**
1. Check service status:
   ```bash
   systemctl status pouw-node
   ```

2. Restart if needed:
   ```bash
   systemctl restart pouw-node
   ```

3. Check for crash dump:
   ```bash
   coredumpctl list pouw-node
   ```

**Investigation:**
1. Review logs before crash
2. Check resource usage (memory, disk)
3. Look for panic messages

## Scaling Procedures

### Vertical Scaling

1. Stop service gracefully:
   ```bash
   systemctl stop pouw-node
   ```

2. Resize VM/container

3. Update configuration for new resources

4. Start service:
   ```bash
   systemctl start pouw-node
   ```

5. Verify health

### Horizontal Scaling

1. Deploy new node with same configuration

2. Add to load balancer

3. Verify traffic distribution

4. Monitor for consistency issues

## Maintenance Procedures

### Database Maintenance

Weekly:
```sql
-- Update statistics
VACUUM ANALYZE;

-- Check table sizes
SELECT relname, pg_size_pretty(pg_total_relation_size(relid))
FROM pg_stat_user_tables
ORDER BY pg_total_relation_size(relid) DESC;
```

Monthly:
```sql
-- Purge old challenges (> 7 days)
DELETE FROM challenges WHERE expires_at < NOW() - INTERVAL '7 days';

-- Purge old nonces (> 24 hours)
DELETE FROM used_nonces WHERE created_at < NOW() - INTERVAL '24 hours';

-- Archive old receipts (> 90 days)
INSERT INTO receipts_archive SELECT * FROM receipts WHERE submitted_at < NOW() - INTERVAL '90 days';
DELETE FROM receipts WHERE submitted_at < NOW() - INTERVAL '90 days';
```

### Log Rotation

Logs are rotated automatically. To force rotation:
```bash
logrotate -f /etc/logrotate.d/pouw-node
```

### Certificate Renewal

1. Obtain new certificate
2. Verify chain:
   ```bash
   openssl verify -CAfile chain.pem cert.pem
   ```
3. Update certificate files
4. Reload service:
   ```bash
   systemctl reload pouw-node
   ```

## Dispute Handling

### View Open Disputes
```bash
curl -s http://localhost:8080/api/v1/pouw/disputes?status=open | jq .
```

### Investigate Dispute
```bash
# Get dispute details
curl -s http://localhost:8080/api/v1/pouw/disputes/{dispute_id} | jq .

# Get related receipt
curl -s http://localhost:8080/api/v1/pouw/receipts/{receipt_id} | jq .

# Get client history
curl -s http://localhost:8080/api/v1/pouw/clients/{client_did}/history | jq .
```

### Resolve Dispute
```bash
curl -X POST http://localhost:8080/api/v1/pouw/disputes/{dispute_id}/resolve \
  -H "Content-Type: application/json" \
  -d '{
    "resolution_type": "ClaimantCorrect",
    "explanation": "Verified bug in reward calculation",
    "compensation": {
      "amount": 100,
      "currency": "SOV"
    }
  }'
```

## Emergency Procedures

### Emergency Shutdown
```bash
# Graceful shutdown (finish current requests)
systemctl stop pouw-node

# Force shutdown
systemctl kill pouw-node
```

### Rollback Deployment
```bash
# Switch to previous version
ln -sfn /opt/pouw/releases/previous /opt/pouw/current
systemctl restart pouw-node
```

### Block Malicious Actor
```bash
# Add to firewall blocklist
iptables -A INPUT -s $MALICIOUS_IP -j DROP

# Block DID in application
curl -X POST http://localhost:8080/api/v1/admin/block-did \
  -d '{"did": "did:sov:malicious"}'
```

## Contact Information

| Role | Contact | Hours |
|------|---------|-------|
| On-call Engineer | pager@sovereign.network | 24/7 |
| Database Admin | dba@sovereign.network | Business hours |
| Security Team | security@sovereign.network | 24/7 for P0/P1 |
| Product Owner | product@sovereign.network | Business hours |

## Appendix

### Environment Variables Reference
See [PRODUCTION_CHECKLIST.md](./PRODUCTION_CHECKLIST.md#environment-variables)

### Metric Definitions
See [../monitoring/METRICS.md](../monitoring/METRICS.md)

### API Documentation
See [../api/POUW_API.md](../api/POUW_API.md)
