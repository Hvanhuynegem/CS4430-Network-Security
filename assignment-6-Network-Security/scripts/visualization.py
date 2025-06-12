import subprocess
from collections import Counter
import glob
import os
import matplotlib.pyplot as plt
from datetime import datetime 
from datetime import timezone
import matplotlib.dates as mdates




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
time_bins = Counter()
scanner_targets = {}

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

        output = subprocess.check_output([
            "tshark", "-r", file, "-T", "fields", "-e", "frame.time_epoch", "-e", "ip.src", "-e", "ip.dst"
        ], stderr=subprocess.DEVNULL).decode("utf-8")

        for line in output.strip().split("\n"):
            parts = line.strip().split("\t")
            if len(parts) != 3:
                continue
            ts, src, dst = parts
            if not ts or not src or not dst:
                continue

            # 1. Time bin (5-minute intervals)
            try:
                t = datetime.fromtimestamp(float(ts), tz=timezone.utc)
                bin_timestamp = int(float(ts))  # truncate to integer seconds
                bin_5min = bin_timestamp - (bin_timestamp % 300)  # 300 sec = 5 min
                bin_label = datetime.fromtimestamp(bin_5min, tz=timezone.utc)
                time_bins[bin_label] += 1
            except:
                continue

            # 2. Scanner scope tracking
            if src not in scanner_targets:
                scanner_targets[src] = set()
            scanner_targets[src].add(dst)

    except subprocess.CalledProcessError as e:
        print(f"tshark error for {file}: {e}")

# Sort time bins
sorted_bins = sorted(time_bins.items())

if sorted_bins:
    times, counts = zip(*sorted_bins)

    plt.figure(figsize=(10, 5))
    plt.bar(times, counts, width=300 / (24*60*60), align='center')  # 300 seconds = 5 minutes in days

    plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
    plt.gca().xaxis.set_major_locator(mdates.AutoDateLocator())

    plt.xticks(rotation=45)
    plt.title("Packet Count Over Time (5-Minute Bins)")
    plt.xlabel("Time (UTC)")
    plt.ylabel("Packet Count")
    plt.tight_layout()
    plt.savefig(os.path.join(figures_folder, "packet_time_series.png"))
    plt.show()
else:
    print("No time bin data available for time series plot.")




# Combine both port sets
total_ports = tcp_ports + udp_ports
top_ports = total_ports.most_common(10)

if top_ports:
    ports, counts = zip(*top_ports)
    plt.figure(figsize=(8, 5))
    plt.barh([str(p) for p in ports], counts, color='purple')
    plt.xlabel("Packet Count")
    plt.ylabel("Port")
    plt.title("Top 10 Scanned Ports (TCP + UDP)")
    plt.tight_layout()
    plt.savefig(os.path.join(figures_folder, "top_combined_ports.png"))
    plt.show()


# Count number of IPs scanned by each scanner
scanner_ip_counts = {ip: len(targets) for ip, targets in scanner_targets.items()}
top_scanners = Counter(scanner_ip_counts).most_common(10)

if top_scanners:
    scanners, ip_counts = zip(*top_scanners)
    plt.figure(figsize=(10, 5))
    plt.bar(scanners, ip_counts, color='green')
    plt.title("Top 10 Scanners by Number of Destination IPs")
    plt.xlabel("Source IP")
    plt.ylabel("Unique Destination IPs")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(os.path.join(figures_folder, "scanner_scope.png"))
    plt.show()

else:
    print("No top_scanners data available for bar plot.")