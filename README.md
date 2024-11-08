# Advanced Python Port Scanner

This is an advanced Python port scanner tool that performs multi-threaded scanning, banner grabbing, basic OS fingerprinting, GeoIP lookup, and more. It can scan both TCP and UDP ports, identify services, and retrieve geographical information for public IP addresses.

## Features

- **Multi-threaded Port Scanning**: Scans multiple ports simultaneously to speed up the scanning process.
- **Service Mapping**: Maps common ports to known services (e.g., HTTP on port 80).
- **Banner Grabbing**: Retrieves banners from open ports to identify service versions.
- **UDP Scanning**: Sends basic UDP probes to detect open UDP ports.
- **GeoIP Lookup**: Uses the IPinfo API to retrieve location information for public IPs.
- **OS Fingerprinting**: Provides a basic OS fingerprint based on TTL and TCP window size.
- **HTTP Fingerprinting**: Retrieves HTTP headers from open web ports (e.g., 80, 443) to identify server software.

## Requirements

- **Python 3.x**
- **Requests library** (for GeoIP lookup and HTTP fingerprinting)
- **IPinfo API Key**: Required for reliable GeoIP lookup. You can get a free API key by signing up at [IPinfo](https://ipinfo.io/).

## Installation

1. **Clone the repository**:
    ```bash
    git clone https://github.com/yourusername/advanced-port-scanner.git
    cd advanced-port-scanner
    ```

2. **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

3. **Set up your IPinfo API Key**:
   - In the `advanced_port_scanner.py` script, replace `"b34c4319427fda"` in `IPINFO_API_KEY` with your actual IPinfo API key for the GeoIP lookup to function properly.

## Usage

1. Run the scanner script:
    ```bash
    python advanced_port_scanner.py
    ```

2. Enter the required information:
   - **Target IP**: The IP address or hostname you want to scan.
   - **Port Range**: Specify the starting and ending port numbers (e.g., 1 to 1024).


## File Structure

- **advanced_port_scanner.py**: The main script for the port scanner.
- **requirements.txt**: List of required Python packages.
- **README.md**: Documentation for the project.
- **.gitignore**: Configuration to ignore unnecessary files.

## Setup API Key

1. Create a `.env` file in the project directory.
2. Add your IPinfo API key to the `.env` file:

   ```plaintext
   IPINFO_API_KEY=your_actual_api_key


## License

This project is licensed under the MIT License - see the LICENSE file for details.
