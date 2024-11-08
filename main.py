import socket
import threading
import csv
import time
import random
import requests
import platform
from queue import Queue

# Constants
THREADS = 50
TIMEOUT = 0.5
VERBOSE = True
common_ports = {
    20: "FTP", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    8080: "HTTP Proxy"
}

queue = Queue()
results = []

def log(message, level="INFO"):
    if VERBOSE or level == "ERROR":
        print(f"[{level}] {message}")

def randomize_ports(start_port, end_port):
    ports = list(range(start_port, end_port + 1))
    random.shuffle(ports)
    return ports

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

def geoip_lookup(target):
    try:
        response = requests.get(f'https://ipinfo.io/{target}/json', timeout=TIMEOUT)
        if response.status_code == 200:
            data = response.json()
            log("\n[INFO] GeoIP Location:")
            for key, value in data.items():
                log(f"  {key.capitalize()}: {value}")
    except Exception:
        log("\n[INFO] GeoIP Lookup: Error retrieving location.")

def http_fingerprint(target):
    try:
        url = f"http://{target}"
        response = requests.get(url, timeout=TIMEOUT)
        server = response.headers.get("Server", "Unknown")
        log(f"[HTTP] Server Header: {server}")
    except Exception:
        log(f"[HTTP] Could not retrieve HTTP header from {target}")

def rate_limited_scan(target, port, delay=0.1, backoff=2):
    scan_tcp(target, port)
    scan_udp(target, port)
    time.sleep(delay)
    delay *= backoff

def worker(target):
    while not queue.empty():
        port = queue.get()
        rate_limited_scan(target, port)
        queue.task_done()

def main():
    target = input("Enter the IP address or hostname to scan: ")
    start_port = int(input("Enter the starting port (e.g., 1): "))
    end_port = int(input("Enter the ending port (e.g., 1024): "))
    ports = randomize_ports(start_port, end_port)

    log(f"\nStarting scan on {target} from port {start_port} to {end_port}...")

    geoip_lookup(target)
    os_fingerprint(target)

    if 80 in ports or 443 in ports:
        http_fingerprint(target)

    for port in ports:
        queue.put(port)

    threads = []
    for _ in range(THREADS):
        thread = threading.Thread(target=worker, args=(target,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    # If you'd like to save results to a file, uncomment the following code
    # with open("port_scan_results.csv", mode='w', newline='') as file:
    #     writer = csv.writer(file)
    #     writer.writerow(["Protocol", "Port", "Status", "Service", "Banner"])
    #     writer.writerows(results)
    log("\n[INFO] Port scanning complete.")

if __name__ == "__main__":
    main()
