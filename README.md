# PythMap

PythMap is a powerful network scanning and analysis tool written in Python. It integrates Nmap, banner grabbing, and logging capabilities to assist with network reconnaissance and security assessments.

## Features

- **Nmap port scanning integration**
- **Banner grabbing with service detection**
- **Vulnerability scanning using Nmap NSE scripts**
- **JSON logging with timestamps**
- **Multithreaded scanning for improved performance**
- **Interactive user interface for easy configuration**
- **Root privilege checking and elevation**

## Prerequisites

Before using PythMap, ensure the following dependencies are installed:

- **Python 3.x**
- **Nmap** (must be installed and accessible from the command line)

### Python Dependencies

Install the required Python libraries using:
```bash
pip install python-nmap scapy
```

## Installation

Clone the PythMap repository and navigate to its directory:

```bash
git clone https://github.com/TheBitty/pythmap.git
cd pythmap
mkdir logs  # Create a directory for logs
```

## Usage

Ensure you have a `logs` folder before running the script. To start PythMap, execute:

```bash
sudo python3 scanner.py
```

The script will guide you through the scanning process:

1. Enter the target IP address.
2. Select the port range (common, extended, full, or custom).
3. The script will perform:
   - Port scanning
   - Banner grabbing
   - Vulnerability scanning

Scan results will be displayed in the console and saved to a JSON log file.

## Example Output

```plaintext
Enter target IP: 192.168.1.100  
Scanning 192.168.1.100 for open ports...
Progress: [=================================================] 100%
Found open port: 22
Found open port: 80
Scan completed! Found 2 open ports

Performing banner grabbing...
[+] Banner for port 22: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
[+] Banner for port 80: Apache/2.4.41 (Ubuntu)

Performing vulnerability scan...
Running vulnerability scripts (this may take a while)...

[+] Found potential vulnerabilities on port 22:
  - ssh-auth-methods: none
[+] Found potential vulnerabilities on port 80:
  - http-slowloris-check: VULNERABLE

[+] Scan results saved to scan_192.168.1.100_2025-02-25_09-30-15.json
```

## Log Format

Scan results are logged in timestamped JSON files. Example:

```json
{
    "metadata": {
        "scan_time": "2025-02-25_09-30-15",
        "scan_duration_seconds": 35.8,
        "target_ip": "192.168.1.100",
        "target_hostname": "somehostname.local",
        "ports_scanned": {
            "start": 1,
            "end": 1024,
            "total": 1024
        },
        "open_ports_count": 2
    },
    "open_ports": [
        {
            "port_number": 22,
            "service": "SSH",
            "version": "OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
            "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
            "vulnerabilities": {
                "ssh-auth-methods": "none"
            },
            "scan_time": "09:30:20"
        },
        {
            "port_number": 80,
            "service": "HTTP",
            "version": "Apache/2.4.41 (Ubuntu)",
            "banner": "Apache/2.4.41 (Ubuntu)",
            "vulnerabilities": {
                "http-slowloris-check": "VULNERABLE"
            },
            "scan_time": "09:30:25"
        }
    ]
}
```

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.



