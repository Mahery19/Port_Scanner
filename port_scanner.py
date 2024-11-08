import socket

def port_scan(target, start_port, end_port):
    print(f"Scanning {target} for open ports from {start_port} to {end_port}...\n")
    open_ports = []

    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)  # Timeout for each port check

        result = sock.connect_ex((target, port))
        if result == 0:
            open_ports.append(port)
            print(f"Port {port} is open.")
        sock.close()

    if not open_ports:
        print("\nNo open ports found.")
    else:
        print(f"\nOpen ports on {target}: {open_ports}")

# User Input for Target and Port Range
target = input("Enter the IP address or hostname to scan: ")
start_port = int(input("Enter the starting port (e.g., 1): "))
end_port = int(input("Enter the ending port (e.g., 1024): "))

# Run the Port Scan
port_scan(target, start_port, end_port)
