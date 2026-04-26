#!/usr/bin/env python3
"""Dynamic Ansible inventory that reads hosts from environment variables.

Expects:
  ZHTP_DEPLOY_HOSTS    — comma-separated IPs (required)
  ZHTP_DEPLOY_USER     — SSH user (default: root)
  ZHTP_DEPLOY_SSH_KEY  — path to SSH private key (required)

Usage:
  source .env
  ansible-playbook -i inventory.py playbook.yml
"""

import json
import os
import sys


def main():
    hosts_raw = os.environ.get("ZHTP_DEPLOY_HOSTS", "")
    user = os.environ.get("ZHTP_DEPLOY_USER", "root")
    ssh_key = os.environ.get("ZHTP_DEPLOY_SSH_KEY", "")

    if not hosts_raw or not ssh_key:
        print(
            "Error: ZHTP_DEPLOY_HOSTS and ZHTP_DEPLOY_SSH_KEY must be set.\n"
            "Copy .env.example to .env, fill in your values, then: source .env",
            file=sys.stderr,
        )
        # Return empty inventory so Ansible doesn't crash on --list
        print(json.dumps({"_meta": {"hostvars": {}}}))
        sys.exit(0)

    hosts = [h.strip() for h in hosts_raw.split(",") if h.strip()]

    hostvars = {}
    for host in hosts:
        hostvars[host] = {
            "ansible_user": user,
            "ansible_ssh_private_key_file": os.path.expanduser(ssh_key),
            "ansible_python_interpreter": "/usr/bin/python3",
        }

    inventory = {
        "zhtp_dev": {"hosts": hosts},
        "_meta": {"hostvars": hostvars},
    }

    print(json.dumps(inventory, indent=2))


if __name__ == "__main__":
    main()
