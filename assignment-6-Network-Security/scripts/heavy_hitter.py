import subprocess
import glob
import os
from collections import Counter
import geoip2.database

# Config
target_ip = "185.242.226.50"

pcap_folder = os.path.join(os.path.dirname(__file__), "..", "PCAPs")
pcap_files = sorted(glob.glob(os.path.join(pcap_folder, "*")))

dst_ips = set()
dst_ports = set()
packet_count = 0

for file in pcap_files:
    print(f"Processing {file}")
    try:
        # Extract destination IPs where source IP is the heavy hitter
        output = subprocess.check_output([
            "tshark", "-r", file,
            "-Y", f"ip.src == {target_ip}",
            "-T", "fields", "-e", "ip.dst", "-e", "tcp.dstport", "-e", "udp.dstport"
        ], stderr=subprocess.DEVNULL).decode("utf-8")

        for line in output.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.strip().split("\t")
            if len(parts) >= 1 and parts[0]:
                dst_ips.add(parts[0])
            if len(parts) >= 2 and parts[1].isdigit():
                dst_ports.add(int(parts[1]))
            elif len(parts) >= 3 and parts[2].isdigit():
                dst_ports.add(int(parts[2]))
            packet_count += 1

    except subprocess.CalledProcessError as e:
        print(f"Error reading {file}: {e}")

# GeoIP lookup
geo_folder = os.path.join(os.path.dirname(__file__), "..", "GeoLite2-City")
mmdb_files = glob.glob(os.path.join(geo_folder, "**", "*.mmdb"), recursive=True)

if mmdb_files:
    geoip_db = mmdb_files[0]
else:
    raise FileNotFoundError("GeoLite2-City.mmdb not found in GeoLite2-City folder.")

country = "Unknown"
try:
    with geoip2.database.Reader(geoip_db) as reader:
        response = reader.city(target_ip)
        country = response.country.name
except Exception as e:
    print("GeoIP lookup failed:", e)

# Print summary
print(f"\nHeavy Hitter IP: {target_ip}")
print(f"Total Packets: {packet_count}")
print(f"Unique Destination IPs: {len(dst_ips)}")
print(f"Unique Destination Ports: {len(dst_ports)}")
print(f"Country: {country}")
