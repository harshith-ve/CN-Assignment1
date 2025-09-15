import socket
import json
import datetime

# Server will listen on all interfaces (0.0.0.0) at port 53535
HOST = "0.0.0.0"
PORT = 53535

# Predefined pool of IP addresses that will be allocated based on rules
IP_POOL = [
    "192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5",
    "192.168.1.6", "192.168.1.7", "192.168.1.8", "192.168.1.9", "192.168.1.10", 
    "192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.14", "192.168.1.15"
]

# Rules define how IP addresses are distributed based on the time of day
# Each rule specifies:
# - A time range (hours in 24-hr format)
# - The starting index in the IP_POOL to allocate from
RULES = {
  "morning": {"range": (4, 11), "ip_pool_start": 0},   # 4 AM - 11 AM → use IP_POOL[0..4]
  "afternoon": {"range": (12, 19), "ip_pool_start": 5}, # 12 PM - 7 PM → use IP_POOL[5..9]
  "night": {"range": (20, 23), "ip_pool_start": 10},   # 8 PM - 11 PM → use IP_POOL[10..14]
}

def resolve_ip(header: str):
    """
    Resolve IP address based on custom header and rules.
    Header format: "<HHMMDDYY...XX>" where:
      - First 2 chars = hour of the request (HH)
      - Last 2 chars = sequence ID (XX)

    The rule decides which pool of 5 IPs to use.
    The sequence ID ensures load distribution within that pool.
    """
    hour = int(header[:2])      # Extract hour from header
    seq_id = int(header[-2:])   # Extract sequence ID from header

    # Select which IP pool range to use based on hour
    if 4 <= hour <= 11:
        pool_start = RULES["morning"]["ip_pool_start"]
    elif 12 <= hour <= 19:
        pool_start = RULES["afternoon"]["ip_pool_start"]
    else:  # Covers both 20–23 and 0–3 (night)
        pool_start = RULES["night"]["ip_pool_start"]

    # Distribute requests within the chosen pool of 5 IPs
    index = pool_start + (seq_id % 5)
    return IP_POOL[index]


def server_main():
    """Main function to run the TCP server."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create TCP socket
    sock.bind((HOST, PORT))   # Bind socket to given host and port
    sock.listen(5)            # Start listening, max 5 pending connections
    print(f"[Server] Listening on {HOST}:{PORT}")

    while True:
        # Accept new client connection
        conn, addr = sock.accept()
        print(f"[Server] Connection from {addr}")

        while True:
            # Receive data from client (max 1024 bytes at once)
            data = conn.recv(1024)
            if not data:  # If no data received, client has disconnected
                break

            # Decode message and split into header and domain name
            header, domain = data.decode().split("|")

            # Resolve IP based on header and rules
            ip = resolve_ip(header)

            # Print resolution info on server side
            print(f"[Server] {domain} ({header}) -> {ip}")

            # Send resolved IP back to client
            conn.send(ip.encode())

        conn.close()  # Close client connection when done


if __name__ == "__main__":
    server_main()
