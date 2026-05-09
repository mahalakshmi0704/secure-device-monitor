"""
client.py — Secure Device Monitoring Client
Secure Device Data Monitoring System

Collects real system health metrics using psutil,
encrypts them with AES-256 CBC, and transmits over TCP.
"""

import socket
import time
import struct
import sys
import os
import platform
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))
from crypto_utils import encrypt_data, get_key_fingerprint

try:
    import psutil
except ImportError:
    print("psutil not installed. Run: pip install psutil")
    sys.exit(1)

HOST    = "127.0.0.1"
PORT    = 9999
INTERVAL = 2          # seconds between transmissions
DEVICE_ID = f"{platform.node()}-{platform.system()}"

GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


def collect_metrics(packet_count: int) -> dict:
    """Gather real-time system health metrics via psutil."""
    cpu    = psutil.cpu_percent(interval=0.5)
    ram    = psutil.virtual_memory().percent
    disk   = psutil.disk_usage("/").percent
    net    = psutil.net_io_counters()
    boot   = datetime.fromtimestamp(psutil.boot_time()).isoformat()

    return {
        "device_id"     : DEVICE_ID,
        "timestamp"     : datetime.now().isoformat(timespec="seconds"),
        "packet_count"  : packet_count,
        "cpu_percent"   : cpu,
        "ram_percent"   : ram,
        "disk_percent"  : disk,
        "bytes_sent"    : net.bytes_sent,
        "bytes_recv"    : net.bytes_recv,
        "cpu_cores"     : psutil.cpu_count(logical=True),
        "platform"      : platform.system(),
        "python_version": platform.python_version(),
        "boot_time"     : boot,
    }


def send_with_framing(sock: socket.socket, encrypted: bytes):
    """Send length-prefixed message: [4-byte length][payload]."""
    length_header = struct.pack("!I", len(encrypted))
    sock.sendall(length_header + encrypted)


def run_client():
    print(f"\n{BOLD}{'═'*55}")
    print(f"   📡 SECURE DEVICE MONITORING CLIENT")
    print(f"{'═'*55}{RESET}")
    print(f"   Device   : {DEVICE_ID}")
    print(f"   Target   : {HOST}:{PORT}")
    print(f"   Interval : {INTERVAL}s")
    print(f"   AES Key  : {get_key_fingerprint()}  (fingerprint)")
    print(f"{'═'*55}\n")

    packet_count = 0

    while True:
        try:
            print(f"{CYAN}[*] Connecting to server...{RESET}")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((HOST, PORT))
            print(f"{GREEN}[+] Connected! Transmitting encrypted metrics...{RESET}\n")

            while True:
                packet_count += 1
                metrics = collect_metrics(packet_count)

                # ── Encrypt ────────────────────────────────────────────────
                encrypted = encrypt_data(metrics)

                # ── Transmit ───────────────────────────────────────────────
                send_with_framing(sock, encrypted)

                cpu_c = RED if metrics["cpu_percent"] > 80 else (YELLOW if metrics["cpu_percent"] > 50 else GREEN)

                print(
                    f"  {BOLD}#{packet_count:04d}{RESET} | "
                    f"{metrics['timestamp']} | "
                    f"CPU: {cpu_c}{metrics['cpu_percent']:5.1f}%{RESET} | "
                    f"RAM: {metrics['ram_percent']:5.1f}% | "
                    f"Disk: {metrics['disk_percent']:5.1f}% | "
                    f"{GREEN}✓ Encrypted & Sent ({len(encrypted)} bytes){RESET}"
                )

                time.sleep(INTERVAL)

        except ConnectionRefusedError:
            print(f"{RED}[!] Server not reachable. Retrying in 5s...{RESET}")
            time.sleep(5)
        except (ConnectionResetError, BrokenPipeError):
            print(f"{YELLOW}[-] Connection lost. Reconnecting in 3s...{RESET}")
            time.sleep(3)
        except KeyboardInterrupt:
            print(f"\n{YELLOW}[*] Client stopped. Total packets sent: {packet_count}{RESET}")
            break
        finally:
            try:
                sock.close()
            except Exception:
                pass


if __name__ == "__main__":
    run_client()
