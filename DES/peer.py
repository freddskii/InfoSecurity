import sys
import os
import socket
import struct
import threading
from des import des_cbc_encrypt, des_cbc_decrypt

PRE_SHARED_KEY = os.environ.get("DES_KEY", "INFOS3C!").encode("utf-8")
if len(PRE_SHARED_KEY) != 8:
    raise ValueError("Pre-shared key must be exactly 8 bytes (64 bits)")

DEFAULT_PORT = 5000

def send_exact(sock: socket.socket, data: bytes):
    sock.sendall(data)

def recv_exact(sock: socket.socket, num_bytes: int) -> bytes:
    buf = bytearray()
    while len(buf) < num_bytes:
        chunk = sock.recv(num_bytes - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def receive_thread(sock: socket.socket, stop_event: threading.Event, encrypted: bool):
    while not stop_event.is_set():
        try:
            len_bytes = recv_exact(sock, 4)
            if not len_bytes:
                print("\n[*] Remote peer disconnected.")
                stop_event.set()
                break

            msg_len = struct.unpack("!I", len_bytes)[0]

            payload = recv_exact(sock, msg_len)
            if not payload:
                print("\n[*] Remote peer disconnected.")
                stop_event.set()
                break

            if encrypted:
                plaintext_bytes = des_cbc_decrypt(payload, PRE_SHARED_KEY)
                plaintext = plaintext_bytes.decode("utf-8", errors="replace")
                print("\n" + "=" * 50)
                print(f"[RECEIVED CIPHERTEXT (HEX)]\n{payload.hex().upper()}")
                print(f"[DECRYPTED PLAINTEXT]\n{plaintext}")
                print("=" * 50)
            else:
                plaintext = payload.decode("utf-8", errors="replace")
                print("\n" + "=" * 50)
                print(f"[RECEIVED UNENCRYPTED PLAINTEXT]\n{plaintext}")
                print(f"[RAW BYTES (HEX)]\n{payload.hex().upper()}")
                print("=" * 50)

            print("Type a message (or 'exit'): ", end="", flush=True)

        except Exception as e:
            if not stop_event.is_set():
                print(f"\n[!] Error receiving message: {e}")
                stop_event.set()
            break


def send_thread(sock: socket.socket, stop_event: threading.Event, encrypted: bool):
    """Thread to read input, encrypt (if enabled), and send over socket."""
    while not stop_event.is_set():
        try:
            msg = input("Type a message (or 'exit'): ").strip()
            if not msg:
                continue

            if msg.lower() in ("exit", "quit"):
                stop_event.set()
                break

            if encrypted:
                payload = des_cbc_encrypt(msg.encode("utf-8"), PRE_SHARED_KEY)
                print("-" * 50)
                print(f"[SENT PLAINTEXT]        : {msg}")
                print(f"[SENT CIPHERTEXT (HEX)] : {payload.hex().upper()}")
                print("-" * 50)
            else:
                payload = msg.encode("utf-8")
                print("-" * 50)
                print(f"[SENT UNENCRYPTED MSG]  : {msg}")
                print(f"[SENT RAW BYTES (HEX)]  : {payload.hex().upper()}")
                print("-" * 50)

            packet = struct.pack("!I", len(payload)) + payload

            send_exact(sock, packet)

        except (EOFError, KeyboardInterrupt):
            stop_event.set()
            break
        except Exception as e:
            print(f"\n[!] Error sending message: {e}")
            stop_event.set()
            break


def run_listen(port: int, encrypted: bool = True):
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("0.0.0.0", port))
    server_sock.listen(1)

    mode_label = "ENCRYPTED (DES-CBC)" if encrypted else "UNENCRYPTED (PLAINTEXT CONTRAST)"
    print(f"[*] Mode: {mode_label}")
    print(f"[*] Listening on 0.0.0.0:{port}...")
    if encrypted:
        print(f"[*] Pre-shared Key (hex): {PRE_SHARED_KEY.hex().upper()} ('{PRE_SHARED_KEY.decode(errors='ignore')}')")
    print("[*] Waiting for incoming peer connection...")

    conn, addr = server_sock.accept()
    print(f"[+] Connected to peer at {addr[0]}:{addr[1]}")
    handle_connection(conn, encrypted)
    server_sock.close()


def run_connect(host: str, port: int, encrypted: bool = True):
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mode_label = "ENCRYPTED (DES-CBC)" if encrypted else "UNENCRYPTED (PLAINTEXT CONTRAST)"
    print(f"[*] Mode: {mode_label}")
    print(f"[*] Connecting to peer at {host}:{port}...")
    if encrypted:
        print(f"[*] Pre-shared Key (hex): {PRE_SHARED_KEY.hex().upper()} ('{PRE_SHARED_KEY.decode(errors='ignore')}')")
    conn.connect((host, port))
    print(f"[+] Successfully connected to {host}:{port}")
    handle_connection(conn, encrypted)


def handle_connection(conn: socket.socket, encrypted: bool):
    stop_event = threading.Event()

    t_recv = threading.Thread(target=receive_thread, args=(conn, stop_event, encrypted), daemon=True)
    t_recv.start()

    send_thread(conn, stop_event, encrypted)

    try:
        conn.shutdown(socket.SHUT_RDWR)
    except Exception:
        pass
    conn.close()
    print("\n[*] Connection closed.")


def print_usage():
    print("Usage:")
    print("  Encrypted (Default):")
    print("    python3 peer.py listen [port]")
    print("    python3 peer.py connect <host> [port]")
    print("\n  Unencrypted (Plaintext contrast for Wireshark):")
    print("    python3 peer.py listen [port] --plaintext")
    print("    python3 peer.py connect <host> [port] --plaintext")
    print(f"\n  Default port : {DEFAULT_PORT}")


def main():
    raw_args = sys.argv[1:]
    encrypted = True

    args = []
    for arg in raw_args:
        if arg in ("--plain", "--plaintext"):
            encrypted = False
        else:
            args.append(arg)

    if not args or args[0] in ("-h", "--help"):
        print_usage()
        print("\nInteractive Quick Start:")
        mode_choice = input("Select mode [1] Listen (Server) or [2] Connect (Client): ").strip()
        enc_choice = input("Enable DES encryption? ([y]/n): ").strip().lower()
        if enc_choice == "n":
            encrypted = False

        if mode_choice == "1":
            port_input = input(f"Port [{DEFAULT_PORT}]: ").strip()
            port = int(port_input) if port_input else DEFAULT_PORT
            run_listen(port, encrypted)
        elif mode_choice == "2":
            host = input("Remote Host IP: ").strip()
            port_input = input(f"Port [{DEFAULT_PORT}]: ").strip()
            port = int(port_input) if port_input else DEFAULT_PORT
            run_connect(host, port, encrypted)
        else:
            print("Invalid selection.")
        return

    mode = None
    host = "127.0.0.1"
    port = DEFAULT_PORT

    if args[0] in ("listen", "server"):
        mode = "listen"
        if len(args) > 1:
            port = int(args[1])
    elif args[0] in ("connect", "client"):
        mode = "connect"
        if len(args) > 1:
            host = args[1]
        if len(args) > 2:
            port = int(args[2])
    else:
        i = 0
        while i < len(args):
            if args[i] == "--mode" and i + 1 < len(args):
                mode = args[i + 1]
                i += 2
            elif args[i] == "--host" and i + 1 < len(args):
                host = args[i + 1]
                i += 2
            elif args[i] == "--port" and i + 1 < len(args):
                port = int(args[i + 1])
                i += 2
            else:
                i += 1

    if mode == "listen":
        run_listen(port, encrypted)
    elif mode == "connect":
        run_connect(host, port, encrypted)
    else:
        print_usage()


if __name__ == "__main__":
    main()