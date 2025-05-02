from scapy.all import *

def handle_packet(packet):
	print('sniffed packet:', packet)


sniffer = AsyncSniffer(
	iface="eth0", 
	prn=handle_packet, 
	store=False
)

# Start the sniffer
sniffer.start()


print("sending ping")
# Send a packet to trigger the sniffer
packet = IP(dst="192.168.124.10")/ICMP()

# Send the packet
send(packet)
