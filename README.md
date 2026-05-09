# secure-device-monitor
Python system to collect and transmit device health metrics over AES-256 encrypted socket connections
# 🔐 Secure Device Data Monitoring System

A Python system to collect and transmit device health metrics over AES-256 encrypted socket connections.

## Features
- **AES-256-CBC encryption** with a fresh random IV per packet — prevents replay attacks
- **Multi-threaded TCP server** handles multiple devices simultaneously  
- **Real-time metrics** — CPU, RAM, disk, network via `psutil`
- **Length-framed socket protocol** for reliable partial-read handling
- **Automatic reconnection** if the server drops

## Tech Stack
Python · PyCryptodome · psutil · Socket Programming · TCP/IP · AES-256

## Run It
```bash
pip install pycryptodome psutil

# Terminal 1
python server.py

# Terminal 2  
python client.py

# Or full demo in one window
python demo.py
```

## Security Design
| Feature | Detail |
|---|---|
| Algorithm | AES-256-CBC |
| Key size | 256-bit (SHA-256 derived) |
| IV | Random 16 bytes per packet |
| Padding | PKCS7 |
| MITM protection | Encrypted payload unreadable in transit |
