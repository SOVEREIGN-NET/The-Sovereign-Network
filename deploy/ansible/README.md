# ZHTP Node Ansible Deployment

Ansible playbook for deploying ZHTP nodes to Linux servers.

## Supported Distributions

| Distro | Package Manager | Firewall | Init System |
|--------|----------------|----------|-------------|
| Ubuntu/Debian | apt | UFW | systemd |
| RHEL/CentOS/Fedora | dnf | firewalld | systemd |
| Arch Linux | pacman | iptables | systemd |
| Alpine | apk | iptables | OpenRC |

## Prerequisites

- Ansible installed locally: `pip install ansible` or `brew install ansible`
- SSH key access to target server

## Configuration

Host credentials are loaded from **environment variables** so that IPs and
key paths stay out of version control.

```bash
cd deploy/ansible

# 1. Copy the example env file and fill in your values
cp .env.example .env
# Edit .env with your real IPs, SSH user, and key path

# 2. Source it
source .env
```

The `.env` file sets three variables:

| Variable | Description | Example |
|----------|-------------|---------|
| `ZHTP_DEPLOY_HOSTS` | Comma-separated target IPs | `10.0.1.5,10.0.1.6` |
| `ZHTP_DEPLOY_USER` | SSH user | `root` |
| `ZHTP_DEPLOY_SSH_KEY` | Path to SSH private key | `~/.ssh/id_ed25519` |

The dynamic inventory script (`inventory.py`) reads these variables and
generates the Ansible host list automatically.

## Usage

```bash
cd deploy/ansible
source .env

# Test connection
ansible all -m ping

# Setup server (dependencies, firewall, directories)
ansible-playbook playbook.yml

# Deploy new binary (after building locally)
ansible-playbook playbook.yml -e "deploy_binary=true"

# Dry run (check mode)
ansible-playbook playbook.yml --check

# Skip service start (setup only)
ansible-playbook playbook.yml -e "start_service=false"

# Target specific host
ansible-playbook playbook.yml --limit 10.0.1.5
```

## What It Does

1. **Installs system dependencies** (distro-specific packages)

2. **Creates `/opt/zhtp` directory**

3. **Configures firewall** (auto-detects UFW/firewalld/iptables):
   - TCP 22 (SSH)
   - UDP 37775 (multicast discovery)
   - TCP 33444 (mesh networking)
   - TCP 9334 (API port)

4. **Deploys service file** (systemd or OpenRC)

5. **Optionally deploys the binary** from `target/release/zhtp`

## Building the Binary

Before deploying with `deploy_binary=true`:

```bash
# From project root
cargo build --release -p zhtp
```

## Service Management

### Systemd (Ubuntu, RHEL, Arch)

```bash
systemctl status zhtp
journalctl -u zhtp -f
systemctl restart zhtp
systemctl stop zhtp
```

### OpenRC (Alpine)

```bash
rc-service zhtp status
tail -f /var/log/messages | grep zhtp
rc-service zhtp restart
rc-service zhtp stop
```

## Troubleshooting

### SSH Locked Out

Use VPS provider's console:

```bash
# Ubuntu/Debian
ufw allow 22/tcp && ufw reload

# RHEL/CentOS
firewall-cmd --add-port=22/tcp --permanent && firewall-cmd --reload

# Arch/Alpine
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
```

### Host Key Changed

```bash
ssh-keygen -R <ip-address>
```

### Check Detected OS

```bash
ansible all -m setup -a "filter=ansible_os_family"
ansible all -m setup -a "filter=ansible_service_mgr"
```
