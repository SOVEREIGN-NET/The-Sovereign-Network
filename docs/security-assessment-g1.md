# Security Assessment — zhtp-g1 (77.42.37.161)
**Date:** 2026-04-11  
**OS:** Ubuntu 24.04.3 LTS — Kernel 6.8.0-88-generic  
**Purpose:** Validator node — single purpose, no other workloads

---

## CRITICAL — Fix Immediately

### 1. Firewall is OFF
```
ufw status: inactive
iptables: policy ACCEPT on all chains — no rules
```
The server has zero network filtering. Every port is reachable from the internet. This is the single most dangerous configuration on the machine.

**Right now, the server is being brute-forced:**
```
47.96.109.25   — scanning: kafka, mysql, postgres, deploy, oracle, www, test
45.148.10.157  — brute-forcing root with password
92.118.39.56   — brute-forcing invalid users
45.148.10.183  — brute-forcing ubuntu
102.216.134.50 — brute-forcing root
186.96.145.241 — brute-forcing git
```
These are happening continuously, right now. Port 22 is fully exposed to the internet with root login enabled.

---

### 2. Root SSH login with password enabled
```
PermitRootLogin yes
KbdInteractiveAuthentication no  ← keyboard-interactive off, but PAM is on
UsePAM yes                        ← PAM enables password auth paths
```
Combined with no firewall = the server is one weak password away from full compromise. The only thing protecting it is the single ed25519 key in `authorized_keys` — but `PermitRootLogin yes` with PAM enabled leaves password authentication paths open depending on PAM stack configuration.

---

### 3. zhtp runs as root
```
root 208577 /opt/zhtp/zhtp --testnet
```
If zhtp has any exploitable bug (memory corruption, RCE via malformed QUIC packet), the attacker gets an immediate root shell with no privilege escalation needed. A dedicated `zhtp` user with no shell would contain any compromise to that user's scope.

---

### 4. X11Forwarding enabled
```
X11Forwarding yes
```
A validator node has no display. This opens an X11 forwarding attack surface for no reason.

---

## HIGH — Fix This Week

### 5. No brute-force protection (fail2ban / sshguard)
Port 22 is being hammered continuously. Nothing is blocking or rate-limiting these attempts. With no firewall and root login enabled, this is a live attack in progress.

### 6. Snapd installed and enabled (7 services)
```
snapd.service
snapd.apparmor.service
snapd.autoimport.service
snapd.core-fixup.service
snapd.recovery-chooser-trigger.service
snapd.seeded.service
snapd.system-shutdown.service
```
Snapd is a large daemon with a persistent socket, auto-update logic, and network calls. A validator node will never install a snap. This is pure attack surface with zero utility.

### 7. Build tools on a production node
```
build-essential, gcc-13, g++-13, clang-18, binutils, cpp
```
If an attacker gets a foothold, these let them compile exploits locally. Remove entirely. The zhtp binary is deployed as a prebuilt artifact — the node has no reason to compile anything.

### 8. Unnecessary services running at boot
Services that serve no purpose for a single-purpose validator:

| Service | Why it's there | Remove? |
|---|---|---|
| `atd` | Deferred job scheduler | YES — remove |
| `apport` | Ubuntu crash reporter | YES — remove |
| `open-iscsi` | iSCSI storage initiator | YES — remove |
| `open-vm-tools` | VMware tools | YES — it's a KVM VM, not VMware |
| `vgauth` | VMware guest auth | YES — remove |
| `gpu-manager` | GPU detection | YES — no GPU on this server |
| `pollinate` | Entropy seeding | YES — kernel has its own entropy |
| `multipathd` | Multipath storage | YES — single disk, not needed |
| `man-db` timer | Man page index | YES — remove man-db |
| `sysstat` | perf stat collection | LOW — marginal, can keep or remove |
| `byobu` | Terminal multiplexer | LOW — convenience only, remove |
| `motd-news` timer | Ubuntu news fetch | YES — network call for no reason |
| `update-notifier` | GUI update notifier | YES — no GUI on this server |
| `certbot` | TLS cert renewal | CHECK — does zhtp use a cert? If not, remove |
| `cloud-init` | VM provisioning | DISABLE after initial setup |

### 9. `fs.suid_dumpable = 2` (should be 0)
```
fs.suid_dumpable = 2
```
Value 2 means setuid programs can dump core — which can expose cryptographic keys and memory contents to the filesystem. Should be 0 (no core dumps from setuid processes).

### 10. `kernel.kptr_restrict = 1` (should be 2)
```
kernel.kptr_restrict = 1
```
Value 1 hides kernel pointers from unprivileged users. Value 2 hides them from ALL users including root. On a validator that will never need kernel debugging, use 2.

### 11. Port 5353 (mDNS) open on all interfaces
```
UNCONN 0 0 0.0.0.0:5353  *  zhtp
UNCONN 0 0 *:5353         *  zhtp
```
zhtp is binding to 5353 (mDNS/Zeroconf) on all interfaces including public. This should be loopback-only or disabled entirely if not required for node discovery.

---

## MEDIUM — Fix This Month

### 12. Cloud-init still active after provisioning
Cloud-init runs on every boot and can re-apply configuration if the metadata service is reachable. After initial provisioning, it should be disabled: `touch /etc/cloud/cloud-init.disabled`

### 13. Cron job for backup has no verification
```
0 */6 * * * /opt/zhtp/backup-sled.sh
```
What does this script do? Where does it write? Is the backup encrypted? This needs review.

### 14. `unattended-upgrades` running with default config
Auto-updates are good for security patches but can break a validator mid-operation. Should be configured to only apply security updates and require a manual restart window.

### 15. `rsyslog` duplicates journald
Both `rsyslog` and `systemd-journald` are running. On a single-purpose node with no log aggregation, `rsyslog` is unnecessary — `journalctl` covers everything.

---

## WHAT'S ALREADY GOOD

- Single authorized key (`ssh-ed25519`) — key-based auth is in place
- `kernel.randomize_va_space = 2` — ASLR fully enabled ✓
- `net.ipv4.tcp_syncookies = 1` — SYN flood protection ✓
- `kernel.dmesg_restrict = 1` — dmesg restricted ✓
- `ip_forward = 0` — not acting as a router ✓
- No world-writable files ✓
- Only one non-system interactive user (root) ✓
- Single disk, `ext4` root, no unusual mounts ✓
- `chrony` installed for NTP ✓
- AppArmor enabled ✓
- Disk: 24G used / 75G total — healthy ✓

---

## IMMEDIATE HARDENING SCRIPT

Apply in this order. Do NOT run all at once — confirm each step.

### Step 1 — Firewall (DO THIS FIRST)
```bash
# Allow admin SSH from your IP only
ufw allow from 84.77.194.89 to any port 22 proto tcp

# Allow zhtp QUIC from anywhere (clients + other nodes)
ufw allow 9334/udp

# Allow zhtp P2P port (confirm this is the right port)
ufw allow 37775/udp

# Allow NTP outbound
ufw allow out 123/udp

# Allow DNS outbound
ufw allow out 53

# Enable with default deny
ufw default deny incoming
ufw default allow outgoing
ufw enable
```

### Step 2 — SSH hardening
```bash
cat >> /etc/ssh/sshd_config.d/99-hardened.conf << 'EOF'
PermitRootLogin prohibit-password
PasswordAuthentication no
X11Forwarding no
AllowUsers root
MaxAuthTries 3
LoginGraceTime 20
EOF
systemctl reload ssh
```

### Step 3 — Create dedicated zhtp user
```bash
useradd -r -s /usr/sbin/nologin -d /opt/zhtp zhtp
chown -R zhtp:zhtp /opt/zhtp
# Update zhtp.service: User=zhtp Group=zhtp
# Restart service after
```

### Step 4 — Remove attack surface
```bash
# Snapd
systemctl disable --now snapd snapd.apparmor snapd.seeded
apt-get purge -y snapd
rm -rf /snap /var/snap /var/lib/snapd

# Build tools
apt-get purge -y build-essential gcc g++ clang binutils cpp

# Unnecessary services
apt-get purge -y at apport open-iscsi open-vm-tools byobu

systemctl disable --now gpu-manager vgauth multipathd rsyslog

# Cloud-init (disable, don't remove — needed if you reprovision)
touch /etc/cloud/cloud-init.disabled

# Man pages
apt-get purge -y man-db
```

### Step 5 — Kernel parameters
```bash
cat >> /etc/sysctl.d/99-zhtp-hardened.conf << 'EOF'
# No core dumps from setuid processes
fs.suid_dumpable = 0

# Hide kernel pointers from everyone
kernel.kptr_restrict = 2

# Disable magic SysRq
kernel.sysrq = 0

# Additional network hardening
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_redirects = 0
EOF
sysctl -p /etc/sysctl.d/99-zhtp-hardened.conf
```

### Step 6 — Install fail2ban
```bash
apt-get install -y fail2ban
cat > /etc/fail2ban/jail.d/ssh.conf << 'EOF'
[sshd]
enabled = true
maxretry = 3
bantime = 86400
findtime = 600
EOF
systemctl enable --now fail2ban
```

---

## DISTRO RECOMMENDATION

### Stay on Ubuntu 24.04 LTS (hardened) — short term
Current nodes should be hardened in place using the script above. A distro migration mid-operation is high risk for a running validator.

### Migrate new nodes to Debian 12 (Bookworm) minimal — medium term

**Why Debian over Ubuntu:**

| Factor | Ubuntu 24.04 | Debian 12 Minimal |
|---|---|---|
| Default install size | ~4GB | ~800MB |
| Snapd | Installed by default | Not present |
| Cloud bloat | cloud-init, apport, ubuntu-advantage | None by default |
| Kernel | HWE rolling | Stable, predictable |
| Attack surface | Large default install | Minimal — install only what you need |
| LTS support | 5 years | ~5 years |
| Release cadence | 6 months major | Stable = frozen until next release |

**What to install on Debian minimal:**
```
openssh-server
chrony
ufw
fail2ban
curl
systemd (already there)
# Nothing else — zhtp is a static binary
```

**What NOT to install:**
- No desktop packages
- No snapd
- No cloud-init (unless Hetzner requires it for IP assignment — check)
- No compilers
- No man pages
- No apport, no rsyslog (use journald)

### Do NOT migrate to:
- **Alpine** — musl libc, zhtp is compiled against glibc. Would need recompile + extensive testing.
- **NixOS** — excellent security model but operationally complex for a team running multiple nodes under time pressure.
- **Arch** — rolling release breaks reproducibility.

---

## ROLLING HARDENING ORDER

Apply hardening one node at a time in rolling order: **g1 → g2 → g3**  
Verify consensus is healthy after each node before moving to the next.  
The firewall step (Step 1) is safe to apply first on all nodes — it won't disrupt the running zhtp process.

Most critical order:
1. **Firewall** — apply to all 3 nodes today
2. **SSH hardening** — apply after firewall confirmed working
3. **Remove snapd + build tools** — apply after SSH confirmed
4. **zhtp user** — coordinate with a maintenance window
