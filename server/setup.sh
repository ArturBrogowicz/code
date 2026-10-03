#!/bin/bash

# Zaktualizowana ścieżka na podstawie Twojej aktualnej lokalizacji katalogu
PROJECT_DIR="/home/artur/DDoS-mitigation/code/server"
NGINX_CONF="${PROJECT_DIR}/nginx.conf"
CONTROL_PLANE="${PROJECT_DIR}/control_plane.py"
PYTHON_VENV="/home/artur/DDoS-mitigation/code/venv/bin/python"

if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run this script with root privileges (sudo bash setup.sh)"
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

echo "[*] Configuring paravirtualized interface enp0s8 for XDP..."
ip link set enp0s8 up
# Dodajemy IP, ukrywając błąd w przypadku, gdy adres został już przypisany (jak wynika z 'ip a')
ip addr add 10.0.0.1/24 dev enp0s8 2>/dev/null

# Wyłączenie offloadingu sprzętowego niezbędne do prawidłowego działania XDP
# Dodano wyłączenie GRO i LRO, co jest kluczowe dla sterowników typu virtio_net
ethtool -K enp0s8 tx off rx off gro off lro off 2>/dev/null

echo "[+] Network environment configured: [10.0.0.1 Server listening on enp0s8]"

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
nohup ${PYTHON_VENV} -m gunicorn --chdir ${PROJECT_DIR} --workers 8 --threads 4 -b 0.0.0.0:8080 dummy_app:app >/dev/null 2>&1 &

echo "[*] Starting Nginx directly on the host..."
nginx -c ${NGINX_CONF}

echo "------------------------------------------------------------"
echo "[+] Infrastructure ready! Starting Mitigation Daemon."
echo "------------------------------------------------------------"

${PYTHON_VENV} -u ${CONTROL_PLANE}