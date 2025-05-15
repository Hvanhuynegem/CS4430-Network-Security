from scapy.all import *
from sys import argv

message_bytes = []

def send_icmp_packet(data: bytes, ip_dst: str):
    # Send start marker
    start_pkt = IP(dst=ip_dst, id=0xABCD) / ICMP(type=0, seq=0x0001)
    send(start_pkt, verbose=0)

    # Send message
    for i in range(0, len(data), 4):
        chunk = data[i:i+4].ljust(4, b'\x00')
        ip_id = (chunk[0] << 8) + chunk[1]
        icmp_seq = (chunk[2] << 8) + chunk[3]

        pkt = IP(dst=ip_dst, id=ip_id) / ICMP(type=0, seq=icmp_seq)
        send(pkt, verbose=0)

    # Send stop marker
    stop_pkt = IP(dst=ip_dst, id=0xDCBA) / ICMP(type=0, seq=0xFFFF)
    send(stop_pkt, verbose=0)


def process_packet(pkt):
    global message_bytes

    if IP in pkt and ICMP in pkt:
        ip_id = pkt[IP].id
        icmp_seq = pkt[ICMP].seq

        if ip_id == 0xABCD and icmp_seq == 0x0001:
            message_bytes.clear()

        elif ip_id == 0xDCBA and icmp_seq == 0xFFFF:
            pass  # Do nothing; handled in stop

        else:
            chunk = bytes([
                (ip_id >> 8) & 0xFF, ip_id & 0xFF,
                (icmp_seq >> 8) & 0xFF, icmp_seq & 0xFF
            ])
            message_bytes.append(chunk)

def should_stop(pkt):
    return IP in pkt and ICMP in pkt and pkt[IP].id == 0xDCBA and pkt[ICMP].seq == 0xFFFF


def receive_icmp_packets(timeout=10):
    sniff(filter="icmp", prn=process_packet, stop_filter=should_stop, store=0)
    data = b''.join(message_bytes)
    print(data.decode())


def main():
    if len(argv) != 4:
        if len(argv) != 2:
            print(f"You provided {len(argv) - 1} arguments, but 2 or 4 are required.")
            print("Usage: python3 icmp_covert.py <send> <ip_dst> <message>")
            print("Usage: python3 icmp_covert.py <receive>")
            return
    
    mode = argv[1]
    if mode == "send":
        ip_dst = argv[2]
        message = argv[3]
    elif mode == "receive":
        ip_dst = None   
        message = None
    else:
        print("Invalid mode. Use 'send' or 'receive'.")
        return

    if mode == "send":
        send_icmp_packet(message.encode(), ip_dst)
    elif mode == "receive":        
        # Receive the ICMP packet
        receive_icmp_packets()
    else:
        print("Invalid mode. Use 'send' or 'receive'.")
        return

if __name__ == "__main__":
    main()



