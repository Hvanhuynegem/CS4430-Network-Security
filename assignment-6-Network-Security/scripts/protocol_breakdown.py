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
tcp_packet_count = 0
udp_packet_count = 0
tcp_ports = Counter()
udp_ports = Counter()

for file in pcap_files:
    print(f"Processing: {file}")
    try:
        # Runs tshark script in terminal using the subprocess package for TCP packets
        tcp_out = subprocess.check_output([
            "tshark", "-r", file, "-Y", "tcp.flags.syn==1 and tcp.flags.ack==0", "-T", "fields", "-e", "tcp.dstport"
        ], stderr=subprocess.DEVNULL).decode("utf-8")

        tcp_lines = tcp_out.strip().split("\n")
        tcp_packet_count += len([p for p in tcp_lines if p.strip().isdigit()])
        for port in tcp_lines:
            if port.strip().isdigit():
                tcp_ports[int(port.strip())] += 1

        # Runs tshark script in terminal using the subprocess package for UDP packets
        udp_out = subprocess.check_output([
            "tshark", "-r", file, "-Y", "udp", "-T", "fields", "-e", "udp.dstport"
        ], stderr=subprocess.DEVNULL).decode("utf-8")

        udp_lines = udp_out.strip().split("\n")
        udp_packet_count += len([p for p in udp_lines if p.strip().isdigit()])
        for port in udp_lines:
            if port.strip().isdigit():
                udp_ports[int(port.strip())] += 1

    except subprocess.CalledProcessError as e:
        print(f"tshark error for {file}: {e}")

# prints the results
print("\nProtocol Breakdown:")
print(f"TCP Packets: {tcp_packet_count}")
print(f"UDP Packets: {udp_packet_count}")


# Plot pie chart
labels = ['TCP', 'UDP']
sizes = [tcp_packet_count, udp_packet_count]
colors = ['steelblue', 'darkorange']

plt.figure(figsize=(6, 6))
plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140, colors=colors)
plt.title("TCP vs UDP Packet Distribution")
plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
plt.tight_layout()
plt.savefig(os.path.join(figures_folder, "protocol_breakdown_pie.png"))
plt.show()
