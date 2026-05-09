"""
server.py — Secure Monitoring Server
Secure Device Data Monitoring System

Listens for encrypted device health metrics over TCP.
Decrypts each packet using AES-256 CBC, logs data to JSON file.
"""

import socket
import threading
import json
import os
import sys
import struct
from datetime import datetime

# Add parent dir to path so crypto_utils is importable
sys.path.insert(0, os.path.dirname(__file__))
from crypto_utils import decrypt_data, get_key_fingerprint

HOST = "127.0.0.1"
PORT = 9999
LOG_FILE = os.path.join(os.path.dirname(__file__), "metrics_log.json")

# ─── Colour helpers ──────────────────────────────────────────────────────────
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

connected_clients: dict[str, str] = {}   # addr → device_id
lock = threading.Lock()


def log_metric(record: dict):
    """Append a decrypted metric record to the JSON log file."""
    records = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            try:
                records = json.load(f)
            except json.JSONDecodeError:
                records = []
    records.append(record)
    with open(LOG_FILE, "w") as f:
        json.dump(records, f, indent=2)


def recv_all(conn: socket.socket, length: int) -> bytes:
    """Receive exactly `length` bytes from socket."""
    data = b""
    while len(data) < length:
        chunk = conn.recv(length - len(data))
        if not chunk:
            raise ConnectionError("Client disconnected mid-message")
        data += chunk
    return data


def handle_client(conn: socket.socket, addr: tuple):
    """Handle one connected device client in its own thread."""
    addr_str = f"{addr[0]}:{addr[1]}"
    device_id = "Unknown"

    print(f"\n{GREEN}[+] New connection from {addr_str}{RESET}")

    try:
        while True:
            # ── Length-prefixed framing: 4-byte big-endian uint32 ──────────
            header = recv_all(conn, 4)
            msg_len = struct.unpack("!I", header)[0]

            if msg_len == 0 or msg_len > 1_000_000:
                print(f"{RED}[!] Invalid message length {msg_len} from {addr_str}{RESET}")
                break

            encrypted_payload = recv_all(conn, msg_len)

            # ── Decrypt ────────────────────────────────────────────────────
            data = decrypt_data(encrypted_payload)
            device_id = data.get("device_id", "Unknown")
            ts = data.get("timestamp", "N/A")

            # ── Display ────────────────────────────────────────────────────
            cpu  = data.get("cpu_percent", 0)
            ram  = data.get("ram_percent", 0)
            disk = data.get("disk_percent", 0)

            cpu_color  = RED if cpu  > 80 else (YELLOW if cpu  > 50 else GREEN)
            ram_color  = RED if ram  > 80 else (YELLOW if ram  > 50 else GREEN)
            disk_color = RED if disk > 80 else (YELLOW if disk > 50 else GREEN)

            print(
                f"{CYAN}[{ts}]{RESET} {BOLD}{device_id}{RESET} | "
                f"CPU: {cpu_color}{cpu:5.1f}%{RESET} | "
                f"RAM: {ram_color}{ram:5.1f}%{RESET} | "
                f"Disk: {disk_color}{disk:5.1f}%{RESET} | "
                f"Packets: {data.get('packet_count', '-')}"
            )

            with lock:
                connected_clients[addr_str] = device_id
                log_metric({"received_at": datetime.now().isoformat(), **data})

    except (ConnectionError, ConnectionResetError):
        print(f"{YELLOW}[-] {device_id} ({addr_str}) disconnected{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error with {addr_str}: {e}{RESET}")
    finally:
        with lock:
            connected_clients.pop(addr_str, None)
        conn.close()


def start_server():
    print(f"\n{BOLD}{'═'*55}")
    print(f"   🔒 SECURE DEVICE MONITORING SERVER")
    print(f"{'═'*55}{RESET}")
    print(f"   Host     : {HOST}:{PORT}")
    print(f"   AES Key  : {get_key_fingerprint()}  (SHA-256 fingerprint)")
    print(f"   Log file : {LOG_FILE}")
    print(f"{'═'*55}\n")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(10)

    print(f"{GREEN}[*] Listening for encrypted connections...{RESET}\n")

    try:
        while True:
            conn, addr = server.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[*] Server shutting down.{RESET}")
    finally:
        server.close()


if __name__ == "__main__":
    start_server()
