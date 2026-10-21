#!/bin/bash
set -euxo pipefail
# Bootstrap - Ubuntu 24.04 - Cowrie honeypot
# 1) Move REAL sshd to admin port  2) Cowrie on 2222, NAT 22 -> 2222
# 3) Log shipper to n8n webhook    4) audit + logrotate hygiene

PROJECT="${project}"
REGION="${region}"
WEBHOOK_URL="${webhook_url}"
ADMIN_PORT="${admin_ssh_port}"

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y python3 python3-pip python3-venv git authbind iptables-persistent jq

# --- 1) Real sshd to non-standard admin port (Cowrie will own 22) ---
sed -i "s/^#\?Port .*/Port $ADMIN_PORT/" /etc/ssh/sshd_config
# Cowrie is NOT the real shell - never let real sshd listen on 22 in this lab

# --- 2) Cowrie user + install (venv, unprivileged) ---
id cowrie || useradd -m -s /bin/bash cowrie
sudo -u cowrie git clone https://github.com/cowrie/cowrie.git /home/cowrie/cowrie || true
cd /home/cowrie/cowrie
sudo -u cowrie python3 -m venv cowrie-env
sudo -u cowrie bash -c 'source cowrie-env/bin/activate && pip install --upgrade pip && pip install -r requirements.txt'

# Custom config: repo cowrie/cowrie.cfg -> etc/cowrie.cfg (deploy step copies it)
# Listens on 2222 by default (ssh endpoint in cowrie.cfg: listen_endpoints = tcp:2222)

# systemd unit
cat > /etc/systemd/system/cowrie.service <<'UNIT'
[Unit]
Description=Cowrie SSH Honeypot
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=cowrie
WorkingDirectory=/home/cowrie/cowrie
ExecStart=/home/cowrie/cowrie/cowrie-env/bin/twistd --nodaemon --pidfile= cowrie
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now cowrie || true

# --- Redirect real 22 -> Cowrie 2222 so scanners hitting 22 land in the fake shell ---
iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
netfilter-persistent save || true

systemctl restart ssh || systemctl restart sshd || true

# --- 3) Log shipper (shipper/ship_logs.py is copied to /opt/honeypot-shipper by deploy) ---
mkdir -p /opt/honeypot-shipper /var/log/honeypot-lab
echo "$WEBHOOK_URL" > /opt/honeypot-shipper/.webhook_url
chmod 600 /opt/honeypot-shipper/.webhook_url
cat > /etc/systemd/system/honeypot-shipper.service <<'UNIT'
[Unit]
Description=Honeypot log shipper - Cowrie JSON to n8n webhook
After=cowrie.service network-online.target
[Service]
Type=simple
User=root
WorkingDirectory=/opt/honeypot-shipper
ExecStart=/usr/bin/python3 /opt/honeypot-shipper/ship_logs.py
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
# enable after ship_logs.py is placed (see README deploy steps)
systemctl enable honeypot-shipper || true

echo "Bootstrap complete $(date -u --iso-8601=seconds)" >> /var/log/honeypot-lab/bootstrap.log
