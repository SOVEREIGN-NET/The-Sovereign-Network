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

Edit `inventory.ini` to configure target hosts:

```ini
[zhtp_dev]
77.42.74.80 ansible_user=root ansible_ssh_private_key_file=~/.ssh/kode_ocr.pem
91.98.113.188 ansible_user=root ansible_ssh_private_key_file=~/.ssh/kode_ocr.pem
```

## Usage

```bash
cd deploy/ansible

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
ansible-playbook playbook.yml --limit 77.42.74.80
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
