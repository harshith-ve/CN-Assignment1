# client.py
import socket
import sys
import datetime
import csv
from scapy.all import rdpcap, DNS

SERVER_IP = "10.240.17.208"
SERVER_PORT = 53535

def generate_custom_header(seq_id: int) -> str:
    """Generate HHMMSSID format timestamp + sequence ID."""
    now = datetime.datetime.now()
    hh = now.strftime("%H")
    mm = now.strftime("%M")
    ss = now.strftime("%S")
    return f"{hh}{mm}{ss}{seq_id:02d}"

def extract_dns_queries(pcap_file: str):
    """Return list of (header, domain) from PCAP DNS queries."""
    packets = rdpcap(pcap_file)
    queries = []
    seq_id = 0
    for pkt in packets:
        if pkt.haslayer(DNS) and pkt[DNS].qr == 0:  # query only
            dns_layer = pkt[DNS]
            domain = dns_layer.qd.qname.decode().strip(".")
            header = generate_custom_header(seq_id)
            queries.append((header, domain))
            seq_id += 1
    return queries

def client_main(pcap_file):
    queries = extract_dns_queries(pcap_file)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SERVER_IP, SERVER_PORT))

    report = []
    for header, domain in queries:
        msg = f"{header}|{domain}"
        sock.send(msg.encode())
        response = sock.recv(1024).decode()
        report.append((header, domain, response))
        print(f"[Client] {domain} ({header}) -> {response}")

    sock.close()

    # Save report into CSV
    with open("report.csv", "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Custom Header", "Domain", "Resolved IP"])
        writer.writerows(report)

    print("\n=== Report Saved to report.csv ===")
    print("{:<10} {:<25} {:<15}".format("Header", "Domain", "Resolved IP"))
    for h, d, ip in report:
        print("{:<10} {:<25} {:<15}".format(h, d, ip))

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python client.py <pcap_file>")
        sys.exit(1)
    client_main(sys.argv[1])
