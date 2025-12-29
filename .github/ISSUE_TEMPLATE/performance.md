---
name: "[PERF] Performance Issue or Optimization"
about: Report performance problems or suggest optimizations
title: "[PERF] "
labels: performance
assignees: ''

---

## [PERF] Performance Issue

**What's slow?**
- [ ] Node startup
- [ ] Blockchain sync
- [ ] CLI commands
- [ ] Domain operations
- [ ] Memory usage
- [ ] Disk usage
- [ ] Network throughput
- [ ] Other: [describe]

## Observed Behavior

**Expected Performance:**
[How fast should this be?]

**Actual Performance:**
[How fast is it?]

**Time/Resource Metrics:**
```
- Startup time: X seconds
- Sync time: X minutes  
- Memory usage: X MB
- CPU usage: X%
- Network speed: X Mbps
```

## Steps to Reproduce

```bash
# Commands to reproduce performance issue:
time ./target/release/zhtp node start --config my-node.toml
# or
time ./target/release/zhtp-cli deploy site ./dist --domain myapp.zhtp
```

## Environment

- **Platform:** [macOS/Windows/Linux]
- **Hardware:**
  - CPU: [processor info]
  - RAM: [memory available]
  - Disk: [SSD/HDD, speed if known]
  - Network: [connection speed]
- **Node Configuration:** [relevant settings]
- **Current Version:** [output of `--version`]

## Profiling Data

If available, share profiling results:

```
[Flame graphs, CPU profiles, memory traces, etc.]
```

## Proposed Optimization

Suggestion for improvement (optional):
```
[Potential fix or optimization approach]
```

## Impact

- **Severity:** [Critical/High/Medium/Low]
- **Affected Operations:** [what users can't do efficiently]
- **Frequency:** [happens every time / intermittent / rare]

## Checklist

- [ ] Title includes `[PERF]` prefix
- [ ] Specific metric(s) provided
- [ ] Reproduction steps clear
- [ ] Hardware/environment detailed
- [ ] Baseline vs. actual performance shown
