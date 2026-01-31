# PoUW Failover Scenarios

This document describes failure modes and recovery procedures for the PoUW subsystem.

## Failure Categories

1. **Infrastructure Failures** - Hardware, network, cloud provider issues
2. **Application Failures** - Bugs, resource exhaustion, configuration errors
3. **Data Failures** - Database corruption, replication lag
4. **Security Failures** - Attacks, compromised credentials

---

## Scenario 1: Single Node Failure

### Description
A single PoUW node becomes unavailable due to hardware failure, crash, or network partition.

### Detection
- Health check fails (`/health` returns non-200)
- Load balancer marks node as unhealthy
- Monitoring alerts trigger

### Impact
- Reduced capacity
- Active requests on failed node may timeout
- No data loss (stateless processing)

### Recovery Steps
1. Load balancer automatically routes traffic away (< 30 seconds)
2. Investigate root cause via logs/metrics
3. If hardware: replace and redeploy
4. If software: restart or rollback
5. Add node back to load balancer after health check passes

### Prevention
- Deploy minimum 3 nodes for redundancy
- Use anti-affinity rules to spread across availability zones
- Implement graceful shutdown with connection draining

---

## Scenario 2: Database Primary Failure

### Description
PostgreSQL primary database becomes unavailable.

### Detection
- Application logs show connection errors
- Database health check fails
- Replication lag alerts (if monitoring standby)

### Impact
- All nodes unable to validate receipts or issue challenges
- Service effectively down
- No reward calculations possible

### Recovery Steps

**Automatic (with HA setup):**
1. Standby promotes to primary (< 30 seconds with Patroni/Stolon)
2. Application connections automatically switch
3. Verify data integrity

**Manual:**
1. Identify failure cause
2. If recoverable: restart primary
3. If not recoverable:
   ```bash
   # On standby
   pg_ctl promote -D /var/lib/postgresql/data
   
   # Update connection strings
   # Restart application nodes
   ```
4. Rebuild failed node as new standby

### Prevention
- Deploy with streaming replication
- Use connection pooler (PgBouncer) for automatic failover
- Regular backup verification

---

## Scenario 3: Rate Limiter State Loss

### Description
In-memory rate limiter state is lost (restart, crash, memory pressure).

### Detection
- Spike in requests immediately after restart
- Temporarily higher throughput than expected

### Impact
- Rate limits not enforced for window duration
- Potential for brief DoS vulnerability
- Quick self-healing as new state builds

### Recovery Steps
1. No action required - state rebuilds automatically
2. Monitor for abuse during grace period
3. Consider blocking known bad actors temporarily

### Prevention
- Use Redis-backed rate limiting for persistence
- Implement gradual warmup after restart
- Pre-populate blocklist from recent incidents

---

## Scenario 4: Nonce Storage Failure

### Description
Nonce deduplication storage becomes unavailable.

### Detection
- Errors in validation logs
- Receipts failing with internal errors
- Nonce check timeouts

### Impact
- Cannot validate new receipts (fail-safe)
- Potential for replay attacks if bypassed (fail-unsafe)
- Backlog of unprocessed receipts

### Recovery Steps

**Fail-safe approach (recommended):**
1. Return 503 for all submit requests
2. Fix storage issue
3. Resume processing

**Fail-unsafe approach (emergency only):**
1. Temporarily disable nonce check
2. Log all submissions for later audit
3. Fix storage issue
4. Re-enable nonce check
5. Audit logged submissions for duplicates

### Prevention
- Deploy nonce storage with high availability
- Implement circuit breaker pattern
- Regular backup of nonce database

---

## Scenario 5: Reward Calculation Backlog

### Description
Reward calculation falls behind due to high volume or slow processing.

### Detection
- Growing queue of unprocessed epochs
- Delayed reward distribution
- Client complaints about missing rewards

### Impact
- Delayed but not lost rewards
- Client trust issues
- Potential for double-processing if not careful

### Recovery Steps
1. Identify bottleneck (CPU, database, network)
2. Scale resources if needed
3. Process backlog in batches
4. Verify idempotency of calculations
5. Communicate delays to clients

### Prevention
- Size reward calculation capacity for 2x expected load
- Implement backpressure on receipt ingestion
- Async processing with job queue

---

## Scenario 6: Mass Invalid Signature Submissions

### Description
Large volume of receipts with invalid signatures (attack or client bug).

### Detection
- `invalid_signature` rejection counter spikes
- High CPU usage (signature verification is expensive)
- Legitimate traffic impacted

### Impact
- Resource exhaustion
- Legitimate receipts delayed or dropped
- Potential service degradation

### Recovery Steps
1. Identify source(s) of invalid submissions
2. If concentrated: block at load balancer/firewall
3. If distributed: tighten rate limits temporarily
4. If client bug: notify affected clients

### Prevention
- Implement signature check caching (skip repeat failures)
- Early rejection for malformed requests before signature check
- Client certificate authentication for known clients

---

## Scenario 7: Clock Drift

### Description
Node clock drifts out of sync, causing challenge expiry issues.

### Detection
- Unusual expired challenge rate
- Challenge timestamps in future
- Client complaints about immediate expiry

### Impact
- Valid receipts rejected for expired challenges
- New challenges issued with wrong timestamps
- Trust and reward issues

### Recovery Steps
1. Verify NTP sync:
   ```bash
   timedatectl status
   ntpstat
   ```
2. Force sync if needed:
   ```bash
   systemctl restart chronyd
   ```
3. Review and compensate affected clients

### Prevention
- Deploy NTP with multiple sources
- Monitor clock offset
- Alert on drift > 1 second

---

## Scenario 8: Credential Compromise

### Description
Node signing key or database credentials are compromised.

### Detection
- Unauthorized challenges appearing
- Unusual access patterns in logs
- Security scan alerts

### Impact
- Attacker can issue fake challenges
- Potential for reward theft
- Loss of trust

### Recovery Steps
1. **Immediately:**
   - Rotate compromised credentials
   - Revoke old keys
   - Enable emergency rate limits

2. **Within 1 hour:**
   - Audit all activity since compromise
   - Identify affected clients
   - Block suspicious DIDs

3. **Within 24 hours:**
   - Complete security audit
   - Notify affected parties
   - Implement additional controls

### Prevention
- Use HSM for signing keys
- Secrets management with rotation
- Principle of least privilege
- Regular security audits

---

## Scenario 9: Partial Network Partition

### Description
Some nodes can reach database but not others.

### Detection
- Inconsistent behavior across nodes
- Some health checks pass, others fail
- Split-brain symptoms

### Impact
- Inconsistent validation results
- Potential for duplicate rewards
- Data divergence

### Recovery Steps
1. Identify partition boundary
2. Route all traffic to healthy partition
3. Resolve network issue
4. Verify data consistency
5. Reconcile any discrepancies

### Prevention
- Deploy across multiple availability zones
- Implement partition detection
- Use consensus for critical operations

---

## Scenario 10: Complete Service Outage

### Description
All PoUW nodes and dependencies are unavailable.

### Detection
- All health checks failing
- No metrics being collected
- Complete service unavailability

### Impact
- No challenges issued
- No receipts validated
- No rewards calculated
- Maximum client impact

### Recovery Steps
1. **Assess scope:**
   - Which components are down?
   - Is it regional or global?

2. **Communicate:**
   - Update status page
   - Notify stakeholders

3. **Recover in order:**
   1. Database (primary, then replicas)
   2. Cache layer (Redis if used)
   3. Application nodes (one at a time)
   4. Load balancer configuration

4. **Verify:**
   - End-to-end health check
   - Sample transactions
   - Metrics collection

5. **Post-mortem:**
   - Root cause analysis
   - Timeline of events
   - Improvement actions

### Prevention
- Multi-region deployment
- Regular disaster recovery drills
- Chaos engineering practices

---

## Recovery Time Objectives

| Scenario | RTO | RPO |
|----------|-----|-----|
| Single node failure | 1 min | 0 |
| Database primary failure | 5 min | 1 min |
| Rate limiter state loss | Immediate | N/A |
| Nonce storage failure | 15 min | 0 |
| Complete outage | 30 min | 5 min |

---

## Drill Schedule

| Drill | Frequency | Last Run | Next Run |
|-------|-----------|----------|----------|
| Node failover | Monthly | | |
| Database failover | Quarterly | | |
| Full DR recovery | Annually | | |
| Security incident | Bi-annually | | |
