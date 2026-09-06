#!/bin/bash

PROJECT_DIR="/home/artur/DDoS-mitigation/code"
NGINX_CONF="${PROJECT_DIR}/nginx.conf"
CONTROL_PLANE="${PROJECT_DIR}/control_plane.py"
PYTHON_VENV="${PROJECT_DIR}/venv/bin/python"

if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run this script with root privileges (sudo bash setup_lab.sh)"
  exit
fi

echo "[*] Starting the construction of the automated PoC environment..."

echo "[*] Checking dependencies (Nginx)..."
if ! command -v nginx &> /dev/null; then
    echo "[*] Installing Nginx server..."
    apt-get update && apt-get install -y nginx
fi

systemctl stop nginx 2>/dev/null
systemctl disable nginx 2>/dev/null

echo "[*] Killing old processes from previous sessions..."
pkill -f "nginx: master process" 2>/dev/null
pkill -f "control_plane.py" 2>/dev/null
pkill -f "gunicorn" 2>/dev/null

ip netns del attacker_ns 2>/dev/null
ip netns del server_ns 2>/dev/null

echo "[*] Creating Network Namespaces and veth interfaces..."
ip netns add attacker_ns
ip netns add server_ns

ip link add veth_server type veth peer name veth_attacker

ip link set veth_server netns server_ns
ip link set veth_attacker netns attacker_ns

ip netns exec server_ns ip addr add 10.0.0.1/24 dev veth_server
ip netns exec server_ns ip link set veth_server up
ip netns exec server_ns ip link set lo up

ip netns exec attacker_ns ip addr add 10.0.0.2/24 dev veth_attacker
ip netns exec attacker_ns ip link set veth_attacker up
ip netns exec attacker_ns ip link set lo up

ip netns exec server_ns ethtool -K veth_server tx off rx off

echo "[+] Built network environment: [10.0.0.1 Server] <- veth -> [10.0.0.2 Attacker]"

echo "[*] Preparing logs and SSL certificates for Proxy..."

if [ ! -f /etc/ssl/certs/nginx-selfsigned.crt ]; then
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/ssl/private/nginx-selfsigned.key \
        -out /etc/ssl/certs/nginx-selfsigned.crt \
        -subj "/C=PL/ST=Masovian/L=Warsaw/O=PoC/CN=twojadomena.pl" 2>/dev/null
fi

mkdir -p /var/log/nginx
touch /var/log/nginx/ddos_ml_access.log
chmod 644 /var/log/nginx/ddos_ml_access.log
> /var/log/nginx/ddos_ml_access.log

echo "[*] Creating a robust dummy backend app..."
cat << 'EOF' > ${PROJECT_DIR}/dummy_app.py
def app(environ, start_response):
    data = b"Backend is running flawlessly!\n"
    start_response("200 OK", [
        ("Content-Type", "text/plain"),
        ("Content-Length", str(len(data)))
    ])
    return iter([data])
EOF

echo "[*] Installing Gunicorn inside venv..."
${PYTHON_VENV} -m pip install gunicorn >/dev/null 2>&1

echo "[*] Starting multi-worker Gunicorn backend on port 8080..."
ip netns exec server_ns nohup ${PYTHON_VENV} -m gunicorn --chdir ${PROJECT_DIR} --workers 4 --threads 10 -b 0.0.0.0:8080 dummy_app:app >/dev/null 2>&1 &

echo "[*] Starting Nginx in isolated namespace..."
ip netns exec server_ns nginx -c ${NGINX_CONF}

echo "------------------------------------------------------------"
echo "[+] Infrastructure ready! Starting Mitigation Daemon."
echo "------------------------------------------------------------"

ip netns exec server_ns ${PYTHON_VENV} ${CONTROL_PLANE}
