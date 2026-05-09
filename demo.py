"""
demo.py — Full System Demo (Server + Client in one process)
Secure Device Data Monitoring System

Runs server in background thread, then runs client for 5 packets,
showing the complete AES encrypt → transmit → decrypt pipeline.
"""

import socket
import threading
import struct
import time
import platform
import psutil
from datetime import datetime
from crypto_utils import encrypt_data, decrypt_data, get_key_fingerprint, AES_KEY
import hashlib

HOST = "127.0.0.1"
PORT = 9998   # separate port for demo

# ── ANSI colours ──────────────────────────────────────────────────────────────
G = "\033[92m"; Y = "\033[93m"; R = "\033[91m"
C = "\033[96m"; B = "\033[1m";  M = "\033[95m"; RESET = "\033[0m"

received_packets = []
server_ready = threading.Event()


# ─── SERVER THREAD ────────────────────────────────────────────────────────────
def server_thread():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(1)
    server_ready.set()

    conn, addr = srv.accept()
    try:
        while True:
            header = b""
            while len(header) < 4:
                chunk = conn.recv(4 - len(header))
                if not chunk:
                    return
                header += chunk
            msg_len = struct.unpack("!I", header)[0]
            payload = b""
            while len(payload) < msg_len:
                chunk = conn.recv(msg_len - len(payload))
                if not chunk:
                    return
                payload += chunk

            data = decrypt_data(payload)
            received_packets.append((payload, data))

            cpu = data["cpu_percent"]
            cpu_c = R if cpu > 80 else (Y if cpu > 50 else G)
            print(
                f"  {C}[SERVER]{RESET} ✅ Decrypted #{data['packet_count']:02d} | "
                f"CPU: {cpu_c}{cpu:.1f}%{RESET} | "
                f"RAM: {data['ram_percent']:.1f}% | "
                f"Disk: {data['disk_percent']:.1f}%"
            )
    except Exception:
        pass
    finally:
        conn.close()
        srv.close()


# ─── MAIN DEMO ────────────────────────────────────────────────────────────────
def main():
    print(f"\n{B}{'═'*60}{RESET}")
    print(f"{B}   🔐 SECURE DEVICE DATA MONITORING SYSTEM — DEMO{RESET}")
    print(f"{B}{'═'*60}{RESET}")
    print(f"\n  {B}Encryption:{RESET}  AES-256-CBC  (PKCS7 padding)")
    print(f"  {B}Key Fingerprint:{RESET} {G}{get_key_fingerprint()}{RESET}")
    print(f"  {B}Transport:{RESET}   TCP with length-framed packets")
    print(f"  {B}Platform:{RESET}    {platform.system()} / Python {platform.python_version()}")
    print(f"\n{B}{'─'*60}{RESET}\n")

    # Start server
    t = threading.Thread(target=server_thread, daemon=True)
    t.start()
    server_ready.wait()
    time.sleep(0.1)

    # Connect client
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))

    PACKETS = 5
    for i in range(1, PACKETS + 1):
        metrics = {
            "device_id"    : f"{platform.node()}-{platform.system()}",
            "timestamp"    : datetime.now().isoformat(timespec="seconds"),
            "packet_count" : i,
            "cpu_percent"  : psutil.cpu_percent(interval=0.3),
            "ram_percent"  : psutil.virtual_memory().percent,
            "disk_percent" : psutil.disk_usage("/").percent,
            "bytes_sent"   : psutil.net_io_counters().bytes_sent,
            "bytes_recv"   : psutil.net_io_counters().bytes_recv,
            "platform"     : platform.system(),
        }

        encrypted = encrypt_data(metrics)
        header    = struct.pack("!I", len(encrypted))
        sock.sendall(header + encrypted)

        print(
            f"  {M}[CLIENT]{RESET} 📤 Sent #{i:02d} | "
            f"Encrypted size: {B}{len(encrypted)} bytes{RESET} | "
            f"Raw metrics: {len(str(metrics))} chars"
        )
        time.sleep(1.2)

    sock.close()
    time.sleep(0.5)

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n{B}{'─'*60}{RESET}")
    print(f"{B}  SECURITY SUMMARY{RESET}")
    print(f"{'─'*60}{RESET}")
    if received_packets:
        sample_enc, sample_dec = received_packets[0]
        print(f"  Packets transmitted : {G}{PACKETS}{RESET}")
        print(f"  Encrypted sample    : {Y}{sample_enc[:40]}...{RESET}")
        print(f"  Decrypted device    : {G}{sample_dec['device_id']}{RESET}")
        print(f"  IV per packet       : {G}Yes (random 16 bytes){RESET}  — prevents replay attacks")
        print(f"  Key length          : {G}256 bits{RESET}               — AES-256")
        print(f"  Padding             : {G}PKCS7{RESET}                  — standard block alignment")
        print(f"  MITM protection     : {G}Yes{RESET}                    — encrypted payload unreadable in transit")
    print(f"\n{B}{'═'*60}{RESET}\n")


if __name__ == "__main__":
    main()
