import socket
import threading
import time
import random
import requests
import os
from dotenv import load_dotenv
import platform
from queue import Queue

# Constants
THREADS = 20  # Manageable thread count for controlled speed
TIMEOUT = 1  # Increased timeout for more reliable responses
SCAN_DELAY = 0.2  # Delay between scans to prevent network overload
VERBOSE = True

load_dotenv()
IPINFO_API_KEY = os.getenv("IPINFO_API_KEY")


# Dictionary of common ports and services
common_ports = {
    20: "FTP", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    8080: "HTTP Proxy"
}

# Queue and result storage
queue = Queue()
results = []

# Logging function with verbosity control
def log(message, level="INFO"):
    if VERBOSE or level == "ERROR":
        print(f"[{level}] {message}")

# Shuffle ports to reduce detectability
def randomize_ports(start_port, end_port):
    ports = list(range(start_port, end_port + 1))
    random.shuffle(ports)
    return ports

# TCP scanning function with banner grabbing
def scan_tcp(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        result = sock.connect_ex((target, port))
        if result == 0:
            service = common_ports.get(port, "Unknown")
            banner = banner_grab(target, port) if port in common_ports else "N/A"
            log(f"[TCP] Port {port} is open ({service}) - Banner: {banner}")
            results.append(["TCP", port, "open", service, banner])
        sock.close()
    except Exception:
        pass

# UDP scanning function with basic probe
def scan_udp(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(TIMEOUT)
        if port == 53:  # DNS
            dns_probe = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01'
            sock.sendto(dns_probe, (target, port))
        else:
            sock.sendto(b"", (target, port))
        sock.recvfrom(1024)
        service = common_ports.get(port, "Unknown")
        log(f"[UDP] Port {port} is open ({service})")
        results.append(["UDP", port, "open", service, "N/A"])
    except socket.timeout:
        pass
    except Exception:
        pass

# Function for banner grabbing on open TCP ports
def banner_grab(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((target, port))
        sock.send(b'HEAD / HTTP/1.1\r\n\r\n')
        banner = sock.recv(1024).decode().strip()
        sock.close()
        return banner
    except Exception:
        return "N/A"

# Basic OS fingerprinting using TTL and TCP window size
def os_fingerprint(target):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((target, 80))
        ttl = sock.getsockopt(socket.SOL_IP, socket.IP_TTL)
        window_size = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        sock.close()
        if ttl == 64 and window_size == 5840:
            os_type = "Linux"
        elif ttl == 128 and window_size == 8192:
            os_type = "Windows"
        elif ttl == 255:
            os_type = "Cisco Router"
        else:
            os_type = "Unknown"
        log(f"\n[INFO] OS Fingerprint: {os_type} (TTL={ttl}, Window Size={window_size})")
    except Exception:
        log("\n[INFO] OS Fingerprint: Unable to determine")

# GeoIP lookup using IPinfo API with your token
import ipaddress

def is_public_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False  # Invalid IP address format

def geoip_lookup(target):
    if not is_public_ip(target):
        log("[INFO] GeoIP Lookup: Skipping private IP address.")
        return

    try:
        url = f'https://ipinfo.io/{target}/json?token={IPINFO_API_KEY}'
        response = requests.get(url, timeout=TIMEOUT)
        if response.status_code == 200:
            data = response.json()
            log("\n[INFO] GeoIP Location:")
            for key in ["ip", "city", "region", "country", "org"]:
                log(f"  {key.capitalize()}: {data.get(key, 'N/A')}")
        else:
            log("[INFO] GeoIP Lookup: Could not retrieve location.")
    except Exception:
        log("[INFO] GeoIP Lookup: Error retrieving location.")


# HTTP fingerprinting function to retrieve server header
def http_fingerprint(target):
    try:
        url = f"http://{target}"
        response = requests.get(url, timeout=TIMEOUT)
        server = response.headers.get("Server", "Unknown")
        log(f"[HTTP] Server Header: {server}")
    except Exception:
        log(f"[HTTP] Could not retrieve HTTP header from {target}")

# Rate-limited scan function to control scan speed
def rate_limited_scan(target, port):
    scan_tcp(target, port)
    scan_udp(target, port)
    time.sleep(SCAN_DELAY)

# Worker thread function
def worker(target):
    while not queue.empty():
        port = queue.get()
        rate_limited_scan(target, port)
        queue.task_done()

# Main function
def main():
    target = input("Enter the IP address or hostname to scan: ")
    start_port = int(input("Enter the starting port (e.g., 1): "))
    end_port = int(input("Enter the ending port (e.g., 1024): "))
    ports = randomize_ports(start_port, end_port)

    log(f"\nStarting scan on {target} from port {start_port} to {end_port}...\n")

    log("=== GEOIP INFORMATION ===")
    geoip_lookup(target)

    log("\n=== OS FINGERPRINTING ===")
    os_fingerprint(target)

    log("\n=== HTTP FINGERPRINTING ===")
    if 80 in ports or 443 in ports:
        http_fingerprint(target)

    log("\n=== PORT SCAN RESULTS ===")
    for port in ports:
        queue.put(port)

    threads = []
    for _ in range(THREADS):
        thread = threading.Thread(target=worker, args=(target,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    log("\n[INFO] Port scanning complete.")

if __name__ == "__main__":
    main()
