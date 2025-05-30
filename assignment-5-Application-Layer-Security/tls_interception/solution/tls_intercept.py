from sys import argv
import socket
import ssl
import os
import threading
from OpenSSL import crypto

CERT_DIR = "/tmp/certs"
ROOT_CERT = "/certificate/rootCA.crt"
ROOT_KEY = "/certificate/rootCA.key"


def generate_cert(domain):
    cert_path = f"{CERT_DIR}/{domain}.crt"
    key_path = f"{CERT_DIR}/{domain}.key"

    if os.path.exists(cert_path) and os.path.exists(key_path):
        return cert_path, key_path

    print(f"Generating certificate for {domain}")
    os.makedirs(CERT_DIR, exist_ok=True)

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    cert = crypto.X509()
    cert.get_subject().C = "NL"
    cert.get_subject().CN = domain
    cert.set_serial_number(int.from_bytes(os.urandom(4), byteorder='big'))
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
    cert.set_pubkey(key)

    root_cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(ROOT_CERT).read())
    root_key = crypto.load_privatekey(crypto.FILETYPE_PEM, open(ROOT_KEY).read())
    cert.set_issuer(root_cert.get_subject())
    cert.sign(root_key, "sha256")

    with open(cert_path, "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    with open(key_path, "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

    return cert_path, key_path

def create_ssl_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.set_servername_callback(sni_callback)
    context.load_cert_chain(certfile=ROOT_CERT, keyfile=ROOT_KEY)
    return context

def sni_callback(ssl_sock, server_name, ssl_ctx):
    try:
        cert_path, key_path = generate_cert(server_name)
        ssl_ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
        print(f"Using certificate for {server_name}")
    except Exception as e:
        print(f"Failed to load cert for {server_name}: {e}")

def relay(src, dst):
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            dst.sendall(data)
    except:
        pass
    finally:
        src.close()
        dst.close()

def handle_client(conn, addr, _):
    try:
        client_hello = conn.recv(1024, socket.MSG_PEEK)

        server_name = None
        try:
            sni_offset = client_hello.find(b"\x00\x00")
            if sni_offset != -1:
                sni_data = client_hello[sni_offset + 5:]
                hostname_len = int.from_bytes(sni_data[2:4], 'big')
                server_name = sni_data[4:4 + hostname_len].decode()
        except Exception:
            pass

        if not server_name:
            print("No SNI could be extracted.")
            conn.close()
            return

        print(f"Intercepted domain: {server_name}")
        cert_path, key_path = generate_cert(server_name)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)

        client_ssl = context.wrap_socket(conn, server_side=True)

        upstream = ssl.create_default_context().wrap_socket(
            socket.create_connection((server_name, 443)),
            server_hostname=server_name
        )

        request = client_ssl.recv(4096)
        print(request.decode(errors="ignore"))
        upstream.sendall(request)

        response = upstream.recv(4096)
        print(response.decode(errors="ignore"))
        client_ssl.sendall(response)

        threading.Thread(target=relay, args=(client_ssl, upstream)).start()
        threading.Thread(target=relay, args=(upstream, client_ssl)).start()

    except Exception as e:
        print(f"Error: {e}")
        conn.close()


def main():
    if len(argv) != 2:
        print("Usage: python3 tls_intercept.py <port>")
        exit(1)

    port = int(argv[1])
    ssl_ctx = create_ssl_context()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', port))
    server.listen(5)
    print(f"Listening on port {port}...")

    try:
        while True:
            conn, addr = server.accept()
            print(f"Accepted connection from {addr}")
            threading.Thread(target=handle_client, args=(conn, addr, ssl_ctx)).start()
    except KeyboardInterrupt:
        print("Shutting down.")
        server.close()

if __name__ == "__main__":
    main()
