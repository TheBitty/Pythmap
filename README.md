# NmapPythonScript

A comprehensive network scanning and analysis tool built in Python that combines nmap, banner grabbing, and logging capabilities for network reconnaissance and security assessment.

## Features
- Nmap port scanning integration
- Banner grabbing with service detection
- JSON logging with timestamps
- TCP connection scanning
- Service identification

## Prerequisites
Make sure you have these installed:
- Python 3.x
- Nmap

## Python Dependencies
```bash
pip install python-nmap
pip install scapy
```

## Installation
1. Clone the repository
```bash
git clone https://github.com/yourusername/NmapPythonScript.git
cd NmapPythonScript
```

2. Install dependencies
```bash
pip install -r requirements.txt
```

## Usage
Run the script:
```bash
python3 scanner.py
```

The script will:
1. Prompt for target IP
2. Scan for open ports
3. Attempt banner grabbing
4. Save results to a JSON log file

## Example Output
```
Enter target IP: 10.10.11.50
Scanning 10.10.11.50 for open ports...

Host: 10.10.11.50 ()
State: up

Protocol: tcp
Port: 22, State: open
Port: 80, State: open

Performing banner grabbing...
[+] Banner for port 22: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10
```

## Log Format
Scans are automatically logged to JSON files:
```json
{
    "scan_time": "2025-02-23_15-30-45",
    "target": "10.10.11.50",
    "open_ports": [
        {
            "port_number": 22,
            "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
            "service": "SSH"
        }
    ]
}
```

## Project Structure
```
NmapPythonScript/
│
├── scanner.py          # Main script file
├── requirements.txt    # Python dependencies
├── README.md          # Project documentation
└── scans/             # Directory for scan results
```

## Functions

### scan_ports(target)
Performs port scanning using nmap.
- Parameters: target (str) - IP address to scan
- Returns: list of open ports

### banner_grabbing(target, ports)
Attempts to grab service banners from open ports.
- Parameters: 
  - target (str) - IP address
  - ports (list) - List of ports to check
- Returns: dict of port:banner pairs

### nmap_logger(ports, target)
Logs scan results to JSON file.
- Parameters:
  - ports (list) - List of open ports
  - target (str) - Scanned IP address
- Creates timestamped JSON file with results

## TODO
- Add threading for faster scans
- Implement service version detection
- Add vulnerability checking against known CVEs
- Add WAF detection for web ports
- Implement DNS enumeration
- Add custom service fingerprinting
- Add port knock sequence detection
- Add report generation (HTML, PDF)
- Add database integration for tracking changes
- Add command line arguments for better control
- Implement proxy support
- Add rate limiting options
- Add output filters
- Add custom port ranges
- Add target list support (scan multiple IPs)

## Troubleshooting
Common issues:

1. Permission denied
```bash
# Run with sudo for SYN scans
sudo python3 scanner.py
```

2. Nmap not found
```bash
# Linux
sudo apt-get install nmap

# MacOS
brew install nmap
```

3. Python dependencies
```bash
# If requirements.txt installation fails
pip install python-nmap --user
pip install scapy --user
```

## Legal Notice
This tool is for educational purposes and authorized testing only. Users are responsible for obtaining appropriate permissions before scanning any networks or systems.

## Contributing
1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License
MIT License

## Author
[Your Name]

## Acknowledgments
- Nmap project (https://nmap.org)
- Python-nmap library
- Scapy project
