#!/bin/bash

PROJECT_DIR="/home/artur/DDoS-mitigation/server"
NGINX_CONF="${PROJECT_DIR}/nginx.conf"
CONTROL_PLANE="${PROJECT_DIR}/control_plane.py"
PYTHON_VENV="${PROJECT_DIR}/venv/bin/python"

if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run this script with root privileges (sudo bash setup.sh)"
  exit
fi

echo "[*] Cleaning up old processes..."
systemctl stop nginx 2>/dev/null
systemctl disable nginx 2>/dev/null
pkill -f "nginx: master process" 2>/dev/null
pkill -f "control_plane.py" 2>/dev/null
pkill -f "gunicorn" 2>/dev/null

echo "[*] Configuring interface enp0s8..."
ip addr add 10.0.0.1/24 dev enp0s8 2>/dev/null
ip link set enp0s8 up
# Wyłączenie offloadingu sum kontrolnych niezbędne dla XDP
ethtool -K enp0s8 tx off rx off

if [ ! -f /etc/ssl/certs/nginx-selfsigned.crt ]; then
    echo "[*] Generating SSL certificates..."
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/ssl/private/nginx-selfsigned.key \
        -out /etc/ssl/certs/nginx-selfsigned.crt \
        -subj "/C=PL/ST=Masovian/L=Warsaw/O=PoC/CN=twojadomena.pl" 2>/dev/null
fi

mkdir -p /var/log/nginx
> /var/log/nginx/ddos_ml_access.log
chmod 644 /var/log/nginx/ddos_ml_access.log

echo "[*] Starting Gunicorn..."
nohup ${PYTHON_VENV} -m gunicorn --chdir ${PROJECT_DIR} --workers 8 --threads 4 -b 0.0.0.0:8080 dummy_app:app >/dev/null 2>&1 &
sleep 1

echo "[*] Starting Nginx..."
nginx -c ${NGINX_CONF}

echo "[+] Services running natively. Starting Control Plane."
${PYTHON_VENV} -u ${CONTROL_PLANE}