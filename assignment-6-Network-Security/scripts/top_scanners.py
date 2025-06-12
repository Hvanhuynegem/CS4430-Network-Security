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
ip_counter = Counter()
total_packets = 0

# Count source IPs
ip_counter = Counter()
total_packets = 0

for file in pcap_files:
    print(f"Processing: {file}")
    try:
        # 1. TCP SYN packets (without ACK)
        output_tcp = subprocess.check_output([
            "tshark", "-r", file, "-Y", "tcp.flags.syn==1 and tcp.flags.ack==0",
            "-T", "fields", "-e", "ip.src"
        ], stderr=subprocess.DEVNULL).decode("utf-8")
        ips_tcp = [ip for ip in output_tcp.strip().split("\n") if ip]

        # 2. UDP packets
        output_udp = subprocess.check_output([
            "tshark", "-r", file, "-Y", "udp",
            "-T", "fields", "-e", "ip.src"
        ], stderr=subprocess.DEVNULL).decode("utf-8")
        ips_udp = [ip for ip in output_udp.strip().split("\n") if ip]

        # Combine and count
        ip_counter.update(ips_tcp)
        ip_counter.update(ips_udp)
        total_packets += len(ips_tcp) + len(ips_udp)

    except subprocess.CalledProcessError as e:
        print(f"tshark error for {file}: {e}")


# Output top 10 found IPs.
print("\nTop 10 Scanners:")
print(f"{'IP Address':<20} {'Packets':<10} {'Share (%)':<10}")
for ip, count in ip_counter.most_common(10):
    share = (count / total_packets) * 100
    print(f"{ip:<20} {count:<10} {share:.2f}")

# Plot the output in a table using matplotlib.
top_ips = ip_counter.most_common(10)
ips, counts = zip(*top_ips)
shares = [(c / total_packets) * 100 for c in counts]

# Plot bar chart
plt.figure(figsize=(10, 5))
bars = plt.bar(ips, counts)
plt.title("Top 10 Scanning IPs by Packet Count")
plt.ylabel("Packet Count")
plt.xlabel("Source IP Address")
plt.xticks(rotation=45)

# Annotate bars with % share
for bar, share in zip(bars, shares):
    yval = bar.get_height()
    plt.text(bar.get_x() + bar.get_width()/2.0, yval + 0.01 * max(counts), f"{share:.1f}%", ha='center', va='bottom')

plt.tight_layout()
plt.savefig(os.path.join(figures_folder, "top_scanners.png"))
plt.show()