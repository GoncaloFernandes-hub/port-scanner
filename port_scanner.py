#!/usr/bin/env python3
"""
port_scanner.py
Discovers live hosts on a subnet and scans their ports.
Classifies each port as open, closed, filtered, or inconclusive.
"""

import socket
import threading
import time
import ipaddress
import subprocess
import errno
import argparse


# ── Host discovery ────────────────────────────────────────────────────────────

def is_host_up(host):
    """Send a single ping and return (True, ms) if alive, (False, None) if not."""
    start = time.time()
    result = subprocess.run(
        ["ping", "-c", "1", "-W", "1", host],
        stdout=subprocess.DEVNULL, #Discards standart output
        stderr=subprocess.DEVNULL #Discards error output
    )
    elapsed = (time.time() - start) * 1000
    return (True, elapsed) if result.returncode == 0 else (False, None)


def ping_sweep(subnet):
    """Ping every IP in the subnet and return a list of live hosts."""
    live_hosts = []
    network = ipaddress.ip_network(subnet, strict=False) #Takes a subnet string and turns it into a object you can iterate over

    print(f"\n  Sweeping {subnet}...")

    for ip in network.hosts():
        host = str(ip)
        up, rtt = is_host_up(host)
        if up:
            print(f"  [+] {host} is up  ({rtt:.1f}ms)")
            live_hosts.append(host)

    print(f"\n  Found {len(live_hosts)} host(s).")
    return live_hosts


# ── Port scanning ─────────────────────────────────────────────────────────────

def grab_banner(host, port):
    """
    Connect to an open port and try to read what service is running.
    Some services announce themselves immediately (SSH, FTP).
    Others need a small nudge first (HTTP).
    Returns the first line of the response, or empty string if nothing comes back.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((host, port))
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode(errors="replace").strip()
        sock.close()
        return banner.splitlines()[0] if banner else ""
    except Exception:
        return ""


def scan_port(host, port, timeout=1.0):
    """
        Try a TCP connection to host:port and classify the result.

        How classification works:
        result == 0                -> handshake succeeded -> OPEN
        result == ECONNREFUSED     -> server sent RST (nobody home) -> CLOSED
        anything else (timed out)  -> no reply at all -> ping the host to find out why
            host still responds to ping -> a firewall is blocking this port -> FILTERED
            host doesn't respond       -> can't tell (host down or blocks ICMP) -> INCONCLUSIVE

        Worth knowing:
        Not every CLOSED port is actually closed. Some firewalls are configured to
        actively reject connections by sending a RST packet back, which looks exactly
        like a closed port to us. To tell the difference you'd need an ACK scan —
        sending ACK packets instead of SYN and seeing what drops them silently.
        That's how Nmap's -sA flag works, but it needs raw sockets so it's out of
        scope for this scanner.

        Note: elapsed time is wall-clock time including Python overhead,
        not true network RTT. We use error codes for classification, not timing.
        """
    start = time.time()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    result = sock.connect_ex((host, port))
    sock.close()
    elapsed = (time.time() - start) * 1000

    if result == 0:
        return "OPEN", elapsed
    elif result in (errno.ECONNREFUSED, 111):
        return "CLOSED", elapsed
    else:
        up, _ = is_host_up(host)
        return ("FILTERED" if up else "INCONCLUSIVE"), elapsed


# ── Shared state (written to by multiple threads) ─────────────────────────────

open_ports    = []   # list of (port, elapsed_ms, banner)
filtered_ports = []  # list of (port, elapsed_ms)
closed_count  = 0
lock          = threading.Lock()


def run_scan(host, start_port, end_port, max_threads=100):
    """Scan a range of ports concurrently using threads."""
    sem     = threading.Semaphore(max_threads)
    threads = []

    def worker(port):
        status, elapsed = scan_port(host, port)

        with lock:
            if status == "OPEN":
                banner = grab_banner(host, port)
                open_ports.append((port, elapsed, banner))
            elif status == "FILTERED":
                filtered_ports.append((port, elapsed))
            else:
                global closed_count
                closed_count += 1

        print(f"  Port {port:>5}: {status} ({elapsed:.1f}ms)")
        sem.release()

    print(f"\n  Scanning {host}  (ports {start_port}-{end_port})...")

    for port in range(start_port, end_port + 1):
        sem.acquire()
        t = threading.Thread(target=worker, args=(port,)) #Creates a new worker that runs the function concurrently
        threads.append(t)
        t.start() #Launches the thread

    for t in threads:
        t.join() #This wait so that the threads are finished to move on


# ── Results ───────────────────────────────────────────────────────────────────

def print_summary(host, start_time):
    elapsed = time.time() - start_time

    print(f"\n{'─'*55}")
    print(f"  Scan finished in {elapsed:.2f}s  —  {host}")
    print(f"{'─'*55}")
    print(f"  Open: {len(open_ports)}   Filtered: {len(filtered_ports)}   Closed: {closed_count}")

    if open_ports:
        print(f"\n  Open ports:")
        print(f"  {'PORT':<8} {'TIME':>8}   BANNER")
        print(f"  {'─'*50}")
        for port, ms, banner in sorted(open_ports):
            print(f"  {port:<8} {ms:>6.1f}ms   {banner}")

    if filtered_ports:
        print(f"\n  Filtered ports:")
        print(f"  {'PORT':<8} {'TIME':>8}")
        print(f"  {'─'*20}")
        for port, ms in sorted(filtered_ports):
            print(f"  {port:<8} {ms:>6.1f}ms")

    print(f"\n{'─'*55}\n")


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="A simple network port scanner."
    )
    parser.add_argument("target",
        help="Hostname, IP address, or subnet (e.g. 10.0.0.0/24)")
    parser.add_argument("start_port", nargs="?", type=int, default=1,
        help="First port to scan (default: 1)")
    parser.add_argument("end_port", nargs="?", type=int, default=1024,
        help="Last port to scan (default: 1024)")

    args = parser.parse_args()
    start_time = time.time()

    if "/" in args.target:
        live_hosts = ping_sweep(args.target)
        for host in live_hosts:
            run_scan(host, args.start_port, args.end_port)
            print_summary(host, start_time)
    else:
        print(f"\n  Starting scan on {args.target}")
        run_scan(args.target, args.start_port, args.end_port)
        print_summary(args.target, start_time)