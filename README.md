# 🔍 Port Scanner

A Python network scanner that discovers live hosts on a subnet and scans their ports, classifying each one as open, closed, filtered, or inconclusive.

Built as a networking/cybersecurity project, it combines raw TCP socket programming with multithreading for speed, error-code-based port classification instead of naive timing, and lightweight banner grabbing to identify running services.

## ✨ Features

- **Host discovery** — ping sweep across a subnet to find live hosts before scanning
- **Threaded port scanning** — up to 100 concurrent connections, turning a 17-minute sequential scan into a few seconds
- **Four-way port classification** — `OPEN`, `CLOSED`, `FILTERED`, or `INCONCLUSIVE`, based on TCP error codes rather than response timing
- **Banner grabbing** — reads service banners on open ports (e.g. SSH version, HTTP response) to identify what's actually running
- **Single-host or subnet mode** — scan one target directly, or sweep an entire subnet and scan every live host found
- **Clean summary report** — open/filtered/closed counts and a readable breakdown at the end of every scan

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3 |
| Networking | `socket` (raw TCP), `subprocess` (system ping) |
| Concurrency | `threading` (Thread, Lock, Semaphore) |
| CLI | `argparse` |

## 📁 Project Structure

```
.
└── port_scanner.py     # Everything: host discovery, scanning, banner grabbing, CLI
```

## 🚀 Getting Started

### Prerequisites
- Python 3.10+
- No external dependencies — uses only the standard library

### Installation

```bash
# Clone the repository
git clone https://github.com/GoncaloFernandes-hub/port-scanner.git
cd port-scanner
```

### Running

```bash
# Scan a single host (default: ports 1-1024)
python3 port_scanner.py scanme.nmap.org

# Scan a custom port range
python3 port_scanner.py scanme.nmap.org 1 500

# Sweep a subnet and scan every live host found
python3 port_scanner.py 192.168.1.0/24

# Built-in help
python3 port_scanner.py --help
```

> **Note:** Only scan hosts and networks you own or have explicit permission to test. `scanme.nmap.org` is a legal public target maintained by the Nmap project for this purpose.

## 🧠 How Classification Works

Each port is classified using the TCP connection's error code, not response time, since timing becomes unreliable once network latency is involved:

```
result == 0                → handshake completed              → OPEN
result == ECONNREFUSED     → server sent RST (nobody home)     → CLOSED
anything else (timed out)  → no reply at all:
    host still responds to ping   → a firewall is silently blocking this port → FILTERED
    host doesn't respond to ping  → can't tell (host down, or blocks ICMP too) → INCONCLUSIVE
```

**Known limitation:** some firewalls actively reject connections (sending a RST) rather than silently dropping them. These will show as `CLOSED` even though a firewall is involved. Properly distinguishing this requires an ACK scan (like Nmap's `-sA`), which needs raw sockets and is outside the scope of this project.

## 📊 Example Output

```
Open: 2   Filtered: 4   Closed: 1018

Open ports:
PORT     TIME      BANNER
22       238.7ms   SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
80       266.6ms   HTTP/1.1 200 OK

Filtered ports:
PORT     TIME
53       1081.0ms
515      1037.3ms
```

## 📝 License

This project was developed for educational purposes to learn TCP networking, concurrency, and basic reconnaissance techniques used in cybersecurity.
