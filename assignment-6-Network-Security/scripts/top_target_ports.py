import subprocess
from collections import Counter
import glob
import os
import matplotlib.pyplot as plt


# Locate 12 PCAP files in relative directory
pcap_folder = os.path.join(os.path.dirname(__file__), "..", "PCAPs")

pcap_files = sorted([
    f for f in glob.glob(os.path.join(pcap_folder, "*"))
    if os.path.isfile(f)
])

# Ensure the figure directory exists
figures_folder = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "figures"))
os.makedirs(figures_folder, exist_ok=True)

# Count source IPs
tcp_ports = Counter()
udp_ports = Counter()

for file in pcap_files:
    print(f"Processing: {file}")
    try:
        # Runs tshark script in terminal using the subprocess package for TCP packets
        tcp_out = subprocess.check_output([
            "tshark", "-r", file, "-Y", "tcp", "-T", "fields", "-e", "tcp.dstport"
        ], stderr=subprocess.DEVNULL).decode("utf-8")

        for port in tcp_out.strip().split("\n"):
            if port.strip().isdigit():
                tcp_ports[int(port.strip())] += 1

        # Runs tshark script in terminal using the subprocess package for UDP packets
        udp_out = subprocess.check_output([
            "tshark", "-r", file, "-Y", "udp", "-T", "fields", "-e", "udp.dstport"
        ], stderr=subprocess.DEVNULL).decode("utf-8")

        for port in udp_out.strip().split("\n"):
            if port.strip().isdigit():
                udp_ports[int(port.strip())] += 1

    except subprocess.CalledProcessError as e:
        print(f"tshark error for {file}: {e}")

# Top 10 TCP ports
print("\nTop 10 TCP Destination Ports:")
print(f"{'Port':<8} {'Packets':<10}")
for port, count in tcp_ports.most_common(10):
    print(f"{port:<8} {count:<10}")

# Top 10 UDP ports
print("\nTop 10 UDP Destination Ports:")
print(f"{'Port':<8} {'Packets':<10}")
for port, count in udp_ports.most_common(10):
    print(f"{port:<8} {count:<10}")

# Plot TCP Ports
top_tcp = tcp_ports.most_common(10)
if top_tcp:
    ports_tcp, counts_tcp = zip(*top_tcp)

    plt.figure(figsize=(8, 5))
    plt.barh([str(p) for p in ports_tcp], counts_tcp, color='steelblue')
    plt.xlabel("Packet Count")
    plt.ylabel("TCP Port")
    plt.title("Top 10 TCP Destination Ports")
    plt.tight_layout()
    plt.savefig(os.path.join(figures_folder, "top_tcp_ports.png"))
    plt.show()

# Plot UDP Ports
top_udp = udp_ports.most_common(10)
if top_udp:
    ports_udp, counts_udp = zip(*top_udp)

    plt.figure(figsize=(8, 5))
    plt.barh([str(p) for p in ports_udp], counts_udp, color='darkorange')
    plt.xlabel("Packet Count")
    plt.ylabel("UDP Port")
    plt.title("Top 10 UDP Destination Ports")
    plt.tight_layout()
    plt.savefig(os.path.join(figures_folder, "top_udp_ports.png"))
    plt.show()