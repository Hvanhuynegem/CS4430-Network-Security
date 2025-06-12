import subprocess
import glob
import os
from collections import Counter
import matplotlib.pyplot as plt

# Config
target_ip = "185.242.226.50"

pcap_folder = os.path.join(os.path.dirname(__file__), "..", "PCAPs")
pcap_files = sorted(glob.glob(os.path.join(pcap_folder, "*")))

port_counter = Counter()
dst_ips = set()
packet_count = 0

for file in pcap_files:
    print(f"Processing {file}")
    try:
        # TCP SYN packets
        tcp_out = subprocess.check_output([
            "tshark", "-r", file,
            "-Y", f"ip.src == {target_ip} and tcp.flags.syn==1 and tcp.flags.ack==0",
            "-T", "fields", "-e", "ip.dst", "-e", "tcp.dstport"
        ], stderr=subprocess.DEVNULL).decode("utf-8")

        for line in tcp_out.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.strip().split("\t")
            if len(parts) >= 1 and parts[0]:
                dst_ips.add(parts[0])
            if len(parts) >= 2 and parts[1].isdigit():
                port = int(parts[1])
                port_counter[port] += 1
            packet_count += 1

        # UDP packets
        udp_out = subprocess.check_output([
            "tshark", "-r", file,
            "-Y", f"ip.src == {target_ip} and udp",
            "-T", "fields", "-e", "ip.dst", "-e", "udp.dstport"
        ], stderr=subprocess.DEVNULL).decode("utf-8")

        for line in udp_out.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.strip().split("\t")
            if len(parts) >= 1 and parts[0]:
                dst_ips.add(parts[0])
            if len(parts) >= 2 and parts[1].isdigit():
                port = int(parts[1])
                port_counter[port] += 1
            packet_count += 1

    except subprocess.CalledProcessError as e:
        print(f"Error reading {file}: {e}")

# Print summary
print(f"\nIP: {target_ip}")
print(f"Total Packets: {packet_count}")
print(f"Unique Destination IPs: {len(dst_ips)}")
print(f"Unique Destination Ports: {len(port_counter)}")

# Plot: Packet count per port
plt.figure(figsize=(8, 5))
ports = list(port_counter.keys())
counts = list(port_counter.values())
plt.bar(ports, counts, color='darkred')
plt.xlabel("Destination Port")
plt.ylabel("Packet Count")
plt.title(f"Packets per Port for Heavy Hitter {target_ip}")
plt.xticks(ports)
plt.tight_layout()
plt.savefig("mass_scanner_port_distribution.png", dpi=300)
plt.show()
