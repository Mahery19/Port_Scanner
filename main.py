import socket
import threading
import csv
import platform
import time
import random
from datetime import datetime

# Constants
THREADS = 50
TIMEOUT = 0.5
# OUTPUT_FILE = "port_scan_results.csv"
common_ports = {
    20: "FTP", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    8080: "HTTP Proxy"
}

# Queue for threading
from queue import Queue
queue = Queue()

# Results list for saving to file
results = []

def scan_tcp(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        result = sock.connect_ex((target, port))
        if result == 0:
            service = common_ports.get(port, "Unknown")
            print(f"[TCP] Port {port} is open ({service})")
            results.append(["TCP", port, "open", service])
        sock.close()
    except Exception as e:
        pass

def scan_udp(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(TIMEOUT)
        sock.sendto(b"", (target, port))
        sock.recvfrom(1024)  # Attempt to receive a response
        service = common_ports.get(port, "Unknown")
        print(f"[UDP] Port {port} is open ({service})")
        results.append(["UDP", port, "open", service])
        sock.close()
    except socket.timeout:
        pass  # No response likely means the port is closed
    except Exception as e:
        pass

def os_fingerprint():
    os_name = platform.system()
    os_version = platform.version()
    print(f"\n[INFO] OS Fingerprint: {os_name} {os_version}")
    results.append(["OS", "-", "-", f"{os_name} {os_version}"])

def worker(target):
    while not queue.empty():
        port = queue.get()
        scan_tcp(target, port)
        scan_udp(target, port)
        queue.task_done()

# def save_to_file():
#     with open(OUTPUT_FILE, mode='w', newline='') as file:
#         writer = csv.writer(file)
#         writer.writerow(["Protocol", "Port", "Status", "Service"])
#         writer.writerows(results)
#     print(f"\n[INFO] Results saved to {OUTPUT_FILE}")

def randomize_ports(start_port, end_port):
    ports = list(range(start_port, end_port + 1))
    random.shuffle(ports)
    return ports

def main():
    target = input("Enter the IP address or hostname to scan: ")
    start_port = int(input("Enter the starting port (e.g., 1): "))
    end_port = int(input("Enter the ending port (e.g., 1024): "))
    ports = randomize_ports(start_port, end_port)

    print(f"\nStarting scan on {target} from port {start_port} to {end_port}...")
    os_fingerprint()

    # Fill queue with ports to scan
    for port in ports:
        queue.put(port)

    # Start threads
    threads = []
    for _ in range(THREADS):
        thread = threading.Thread(target=worker, args=(target,))
        threads.append(thread)
        thread.start()

    # Wait for threads to finish
    for thread in threads:
        thread.join()

    # Save results to file
    # save_to_file()
    print("\n[INFO] Port scanning complete.")

if __name__ == "__main__":
    main()
