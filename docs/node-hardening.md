# Validator Node Hardening — Applied Configuration

**Date:** 2026-04-11  
**Nodes:** zhtp-g1, zhtp-g2, zhtp-g3  
**OS:** Ubuntu 24.04.3 LTS — Kernel 6.8.0-107-generic

---

## Network Topology

| Host      | IP              | Endpoint                              | Role      |
|-----------|-----------------|---------------------------------------|-----------|
| zhtp-g1   | 77.42.37.161    | g1.thesovereignnetwork.org:9334       | Validator |
| zhtp-g2   | 77.42.74.80     | g2.thesovereignnetwork.org:9334       | Validator |
| zhtp-g3   | 178.105.9.247   | g3.thesovereignnetwork.org:9334       | Validator |
| zhtp-g4   | 77.42.77.183    | —                                     | Observer  |
| sovn-mail | 91.98.113.188   | —                                     | Mail/Web  |

---

## Hardening Applied

### Firewall (UFW)

All three validator nodes run UFW with default-deny inbound.

```
ufw allow from <admin-ip> to any port 22 proto tcp   # SSH: admin IP only
ufw allow 9334/udp                                    # QUIC (clients + peers)
ufw allow 37775/udp                                   # P2P discovery
ufw allow out 123/udp                                 # NTP
ufw allow out 53                                      # DNS
ufw default deny incoming
ufw default allow outgoing
```

SSH is restricted to the admin's IP. Port 22 is not reachable from the public internet.

---

### SSH Hardening

Applied via `/etc/ssh/sshd_config.d/99-hardened.conf` on all nodes:

```
PermitRootLogin prohibit-password
PasswordAuthentication no
X11Forwarding no
AllowUsers root
MaxAuthTries 3
LoginGraceTime 20
```

Key-only authentication. Password auth disabled at both SSH and PAM layers. X11 forwarding removed (no display on a validator).

---

### Brute-Force Protection (fail2ban)

Installed and active on all nodes. Configuration at `/etc/fail2ban/jail.d/ssh.conf`:

```ini
[sshd]
enabled = true
maxretry = 3
bantime = 86400
findtime = 600
```

3 failed attempts within 10 minutes → 24-hour ban.

---

### zhtp Process User

The `zhtp` binary no longer runs as root. A dedicated system user is created on each node:

```bash
useradd -r -s /usr/sbin/nologin -d /opt/zhtp zhtp
```

The service runs with `User=zhtp Group=zhtp`. The keystore (`~/.zhtp/keystore/`) is owned by the `zhtp` user with 600 permissions. If a remote code execution vulnerability in zhtp were exploited, the attacker would land in the `zhtp` user context with no shell and no write access outside `/opt/zhtp/`.

Service drop-in at `/etc/systemd/system/zhtp.service.d/user.conf`:

```ini
[Service]
User=zhtp
Group=zhtp
Environment=HOME=/opt/zhtp
```

---

### Attack Surface Removed

Packages purged from all nodes:

```bash
# Snapd (persistent socket, auto-update network calls, 7 services)
apt-get purge -y snapd
rm -rf /snap /var/snap /var/lib/snapd

# Build tools (compiler toolchain — no reason to compile on a prod node)
apt-get purge -y build-essential gcc g++ clang binutils cpp

# Unnecessary services
apt-get purge -y at apport open-iscsi open-vm-tools byobu

# Disabled
systemctl disable --now gpu-manager multipathd rsyslog
```

Cloud-init disabled after provisioning:
```bash
touch /etc/cloud/cloud-init.disabled
```

---

### Kernel Parameters

Applied via `/etc/sysctl.d/99-zhtp-hardened.conf`:

```ini
# No core dumps from setuid processes (prevents key material leaking to disk)
fs.suid_dumpable = 0

# Hide kernel pointers from all users including root
kernel.kptr_restrict = 2

# Disable magic SysRq
kernel.sysrq = 0

# Network hardening
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_redirects = 0
```

---

### Package Updates

All nodes updated to latest packages including kernel upgrade from 6.8.0-88/90/91 to **6.8.0-107**. Kernel applied via rolling reboot (one node at a time, verified consensus health between each).

---

## Hardening State Verification

Run this on any node to confirm hardening is in place:

```bash
uname -r                                         # kernel: 6.8.0-107-generic
ufw status                                       # Status: active
ps aux | grep zhtp | grep -v grep | awk '{print $1}'  # user: zhtp
systemctl is-active fail2ban                     # active
grep 'PermitRootLogin' /etc/ssh/sshd_config.d/99-hardened.conf
sysctl -n fs.suid_dumpable                       # 0
sysctl -n kernel.kptr_restrict                   # 2
dpkg -l snapd 2>/dev/null | grep '^ii'           # (no output = removed)
dpkg -l build-essential 2>/dev/null | grep '^ii' # (no output = removed)
```

---

## What Remains

### Pending for All Nodes
- **mDNS (port 5353)** — zhtp binds to `0.0.0.0:5353` on all interfaces. Should be loopback-only or disabled via `enable_mdns = false` in `config.toml` if node discovery via mDNS is not needed.

### Pending for sovn-mail (91.98.113.188)
- Apply equivalent firewall, SSH hardening, fail2ban, and kernel parameter hardening.
- SSH is currently open from all IPs — restrict to admin IP.
- No zhtp process runs on this server.

### Future: New Nodes → Debian 12 Minimal
For any new validator nodes provisioned after this date, prefer **Debian 12 (Bookworm) minimal** over Ubuntu 24.04. The default Ubuntu install ships snapd, cloud-init, apport, and compiler toolchains that must be manually removed. Debian minimal installs none of these.

Required packages on Debian minimal:
```
openssh-server  chrony  ufw  fail2ban  curl
```
Nothing else. `zhtp` is a statically-linked binary — no runtime dependencies.

---

## Node Swap: g3 Migration

During this hardening session, the original g3 server (91.98.113.188) was found to be running nginx, postfix, dovecot, and redis — incompatible with a single-purpose validator. A fresh server (178.105.9.247) was provisioned as the new g3.

Migration procedure:
1. Hardened new server from scratch (UFW, SSH, fail2ban, zhtp user, kernel params)
2. Transferred validator identity (keystore) from old g3 to new g3 — same DID, same consensus key, no validator set change required
3. Transferred blockchain data (`/opt/zhtp/data/testnet/sled/`) to avoid genesis replay issues
4. Stopped zhtp on old server, started on new server — g1+g2 maintained quorum throughout
5. Updated `config.toml` on all nodes to use domain endpoints instead of raw IPs
6. Updated DNS: `g3.thesovereignnetwork.org → 178.105.9.247`
7. Old server renamed to `sovn-mail` in SSH config and documentation

The validator set on-chain was not modified — the same validator identity moved to a new IP, which is transparent to the BFT consensus protocol.
