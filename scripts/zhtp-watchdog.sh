#!/usr/bin/env bash
#
# External QUIC reachability watchdog for ZHTP nodes.
#
# Runs on the same host as zhtp.service. Every WATCHDOG_INTERVAL seconds,
# attempts a QUIC `blockchain status` call against 127.0.0.1:9334 using
# zhtp-cli. After WATCHDOG_FAIL_THRESHOLD consecutive failures, restarts
# zhtp.service.
#
# Why this exists:
#   The Jun-17 2026 gateway outage was caused by a `?` operator in the QUIC
#   accept loop that terminated the loop permanently on the first transient
#   quinn error. The fix is in quic_handler.rs. This watchdog is the
#   belt-and-braces second line of defense for any future failure mode
#   where the process stays alive but stops accepting inbound.
#
# Install:
#   cp scripts/zhtp-watchdog.sh /opt/zhtp/watchdog.sh
#   cp scripts/zhtp-watchdog.service /etc/systemd/system/
#   systemctl enable --now zhtp-watchdog.service

set -u

WATCHDOG_INTERVAL=${WATCHDOG_INTERVAL:-60}
WATCHDOG_FAIL_THRESHOLD=${WATCHDOG_FAIL_THRESHOLD:-3}
WATCHDOG_CLI=${WATCHDOG_CLI:-/opt/zhtp/zhtp-cli}
WATCHDOG_TARGET=${WATCHDOG_TARGET:-127.0.0.1:9334}
WATCHDOG_PROBE_TIMEOUT=${WATCHDOG_PROBE_TIMEOUT:-20}
WATCHDOG_RESTART_CMD=${WATCHDOG_RESTART_CMD:-"systemctl restart zhtp"}
WATCHDOG_BACKOFF_AFTER_RESTART=${WATCHDOG_BACKOFF_AFTER_RESTART:-120}

log() { printf '[%s] watchdog: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

if [[ ! -x "$WATCHDOG_CLI" ]]; then
    log "FATAL: zhtp-cli not found or not executable at $WATCHDOG_CLI"
    exit 2
fi

log "starting (interval=${WATCHDOG_INTERVAL}s, threshold=${WATCHDOG_FAIL_THRESHOLD}, target=${WATCHDOG_TARGET})"

fails=0
last_restart=0

while true; do
    sleep "$WATCHDOG_INTERVAL"

    if timeout "$WATCHDOG_PROBE_TIMEOUT" "$WATCHDOG_CLI" -s "$WATCHDOG_TARGET" blockchain status >/dev/null 2>&1; then
        if [[ $fails -gt 0 ]]; then
            log "probe OK (recovered after $fails failures)"
        fi
        fails=0
        continue
    fi

    fails=$((fails + 1))
    log "probe FAILED ($fails/$WATCHDOG_FAIL_THRESHOLD)"

    if [[ $fails -ge $WATCHDOG_FAIL_THRESHOLD ]]; then
        now=$(date +%s)
        since_last=$(( now - last_restart ))
        if [[ $last_restart -gt 0 && $since_last -lt $WATCHDOG_BACKOFF_AFTER_RESTART ]]; then
            log "skipping restart — last restart was ${since_last}s ago (<$WATCHDOG_BACKOFF_AFTER_RESTART)"
            continue
        fi
        log "RESTARTING zhtp.service: $WATCHDOG_RESTART_CMD"
        # shellcheck disable=SC2086
        $WATCHDOG_RESTART_CMD
        last_restart=$now
        fails=0
        log "restart issued — backing off ${WATCHDOG_BACKOFF_AFTER_RESTART}s before next probe"
        sleep "$WATCHDOG_BACKOFF_AFTER_RESTART"
    fi
done
