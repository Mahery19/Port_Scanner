# Python Port Scanner

A simple Python tool to scan a specified IP address or hostname for open ports within a user-defined range. Port scanning is a fundamental network security technique that helps identify accessible services on a host, and this tool provides a straightforward way to detect open ports.

## Features
- Scans a target IP or hostname for open ports.
- Allows users to specify a range of ports to scan.
- Displays a list of open ports on the target.

## Requirements
- **Python 3.x**
- No external dependencies (only the built-in `socket` library is used).

## Usage

1. Clone the repository:
    ```bash
    git clone https://github.com/yourusername/port-scanner.git
    cd port-scanner
    ```

2. Run the script:
    ```bash
    python port_scanner.py
    ```

3. Enter the required information when prompted:
   - **IP address or hostname** of the target (e.g., `192.168.1.1` or `example.com`).
   - **Starting port** (e.g., `1`).
   - **Ending port** (e.g., `1024`).

### Example

```bash
Enter the IP address or hostname to scan: 192.168.1.1
Enter the starting port (e.g., 1): 20
Enter the ending port (e.g., 80)

Scanning 192.168.1.1 for open ports from 20 to 80...

Port 22 is open.
Port 80 is open.

Open ports on 192.168.1.1: [22, 80]
