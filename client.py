import socket
import sys
import datetime
import csv
from scapy.all import rdpcap, DNS

# Server details – should match the server's IP and port
SERVER_IP = "10.240.17.208"  
SERVER_PORT = 53535

def generate_custom_header(seq_id: int) -> str:
    """
    Generate a custom header for each DNS query.
    Format: HHMMSSID
      - HH = Hour (24-hr)
      - MM = Minute
      - SS = Second
      - ID = 2-digit sequence ID
    Example: "14553207" → 14:55:32, sequence 07
    """
    now = datetime.datetime.now()
    hh = now.strftime("%H")
    mm = now.strftime("%M")
    ss = now.strftime("%S")
    return f"{hh}{mm}{ss}{seq_id:02d}"


def extract_dns_queries(pcap_file: str):
    """
    Extract DNS query packets from a given PCAP file.
    Returns a list of tuples: (custom_header, domain_name).
    
    - Uses Scapy's rdpcap() to read packets.
    - Only DNS queries are extracted (qr == 0).
    - Each query is tagged with a unique header (timestamp + seq_id).
    """
    packets = rdpcap(pcap_file)   # Load all packets from PCAP
    queries = []
    seq_id = 0

    for pkt in packets:
        # Check if the packet contains a DNS layer and is a query (qr == 0)
        if pkt.haslayer(DNS) and pkt[DNS].qr == 0:
            dns_layer = pkt[DNS]
            # Extract the queried domain name (qd.qname), decode from bytes to str, and remove trailing "."
            domain = dns_layer.qd.qname.decode().strip(".")
            # Generate a unique header for this query
            header = generate_custom_header(seq_id)
            queries.append((header, domain))
            seq_id += 1  # Increment sequence ID for next query
    return queries


def client_main(pcap_file):
    """Main client function: read queries, send to server, receive responses, save report."""
    
    # Extract DNS queries from the given PCAP file
    queries = extract_dns_queries(pcap_file)

    # Create a TCP socket and connect to the server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SERVER_IP, SERVER_PORT))

    report = []  # Store results (header, domain, resolved IP)

    for header, domain in queries:
        # Prepare message in format: "<header>|<domain>"
        msg = f"{header}|{domain}"
        sock.send(msg.encode())          # Send to server
        response = sock.recv(1024).decode()  # Receive resolved IP from server
        report.append((header, domain, response))
        print(f"[Client] {domain} ({header}) -> {response}")  # Log resolution

    # Close the socket after processing all queries
    sock.close()

    # Save the report into a CSV file
    with open("report.csv", "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Custom Header", "Domain", "Resolved IP"])
        writer.writerows(report)

    # Print report in tabular format on console
    print("\n=== Report Saved to report.csv ===")
    print("{:<10} {:<25} {:<15}".format("Header", "Domain", "Resolved IP"))
    for h, d, ip in report:
        print("{:<10} {:<25} {:<15}".format(h, d, ip))


if __name__ == "__main__":
    # Ensure user provides the PCAP file as an argument
    if len(sys.argv) != 2:
        print("Usage: python client.py <pcap_file>")
        sys.exit(1)

    # Run main client logic with the provided PCAP file
    client_main(sys.argv[1])
