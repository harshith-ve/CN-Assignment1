# server.py
import socket
import json
import datetime

HOST = "0.0.0.0"
PORT = 53535

IP_POOL = [
    "192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5",
    "192.168.1.6", "192.168.1.7", "192.168.1.8", "192.168.1.9", "192.168.1.10", 
    "192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.14", "192.168.1.15"
]

RULES = {
  "morning": {"range": (4, 11), "ip_pool_start": 0},
  "afternoon": {"range": (12, 19), "ip_pool_start": 5},
  "night": {"range": (20, 23), "ip_pool_start": 10},
}

def resolve_ip(header: str):
    """Resolve IP from header based on rules."""
    hour = int(header[:2])
    seq_id = int(header[-2:])

    # Determine time slot
    if 4 <= hour <= 11:
        pool_start = RULES["morning"]["ip_pool_start"]
    elif 12 <= hour <= 19:
        pool_start = RULES["afternoon"]["ip_pool_start"]
    else:  # 20-23 or 0-3
        pool_start = RULES["night"]["ip_pool_start"]

    index = pool_start + (seq_id % 5)
    return IP_POOL[index]

def server_main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, PORT))
    sock.listen(5)
    print(f"[Server] Listening on {HOST}:{PORT}")

    while True:
        conn, addr = sock.accept()
        print(f"[Server] Connection from {addr}")

        while True:
            data = conn.recv(1024)
            if not data:
                break
            header, domain = data.decode().split("|")
            ip = resolve_ip(header)
            print(f"[Server] {domain} ({header}) -> {ip}")
            conn.send(ip.encode())

        conn.close()

if __name__ == "__main__":
    server_main()
