
import concurrent
import nmap
from scapy.all import *
from datetime import datetime
import json
import socket
from concurrent.futures import ThreadPoolExecutor
import threading
import os
import sys
import ipaddress
import re
import time


def check_root():
    """Check and obtain root privileges"""
    if os.geteuid() != 0:
        print(f"\nPlease run as root")
        print(f"\nAttempting to run as root...")
        try:
            os.execvp('sudo', ['sudo', 'python3'] + sys.argv)
        except Exception as e:
            print(f"\n[-] Failed to obtain root privileges: {e}")
            print(f"\nExiting...please use the sudo command to run the script as root")
            sys.exit(1)


def validate_ip(ip):
    """Validate and clean IP address input"""
    try:
        ip = ip.strip()
        ipaddress.ip_address(ip)
        return ip, True
    except ValueError:
        return ip, False


def get_target_ip():
    """Get and validate target IP with user feedback"""
    while True:
        target = input("Enter target IP: ")
        ip, is_valid = validate_ip(target)

        if is_valid:
            return ip
        else:
            print(f"[-] Invalid IP address: {target}")
            print("[!] Please enter a valid IP (e.g., 192.168.1.1)")
            continue


def get_port_range():
    """Get custom port range from user"""
    while True:
        try:
            print("\nSelect port range to scan:")
            print("1. Common ports (1-1024)")
            print("2. Extended range (1-5000)")
            print("3. Full range (1-65535)")
            print("4. Custom range")

            choice = input("\nEnter choice (1-4): ").strip()

            if choice == '1':
                return 1, 1024
            elif choice == '2':
                return 1, 5000
            elif choice == '3':
                return 1, 65535
            elif choice == '4':
                start = int(input("Enter start port: "))
                end = int(input("Enter end port: "))
                if 0 < start < end <= 65535:
                    return start, end
                else:
                    print("Invalid port range!")
            else:
                print("Invalid choice!")
        except ValueError:
            print("Please enter valid numbers!")


def get_protocol_probe(port):
    """Return appropriate probe for common protocols"""
    probes = {
        21: {  # FTP
            'probe': b"",
            'timeout': 5
        },
        22: {  # SSH
            'probe': b"",
            'timeout': 3
        },
        23: {  # Telnet
            'probe': b"\xff\xfb\x01\xff\xfb\x03\xff\xfd\x0f\xff\xfd\x18",
            'timeout': 5
        },
        25: {  # SMTP
            'probe': b"EHLO test.com\r\n",
            'timeout': 5
        },
        80: {  # HTTP
            'probe': b"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n",
            'timeout': 5
        },
        443: {  # HTTPS
            'probe': b"\x16\x03\x01\x00\x01\x01",
            'timeout': 5
        },
        3306: {  # MySQL
            'probe': b"\x0a",
            'timeout': 5
        }
    }
    return probes.get(port, {'probe': b"", 'timeout': 3})


def get_service_name(port):
    """Identify common services by port number"""
    common_ports = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        443: "HTTPS",
        3306: "MySQL",
        3389: "RDP",
        8080: "HTTP-Proxy",
        8443: "HTTPS-Alt"
    }
    return common_ports.get(port, "Unknown")


class PortScanner:
    def __init__(self):
        self.scanner = nmap.PortScanner()
        self._lock = threading.Lock()

    def scan_port(self, target, port):
        """Thread-safe port scanning"""
        with self._lock:
            try:
                self.scanner.scan(target, str(port), arguments='-sS -Pn -n --host-timeout 30')
                if target in self.scanner.all_hosts():
                    if self.scanner[target].has_tcp(port):
                        return port, self.scanner[target]['tcp'][port]['state']
            except Exception as e:
                print(f"Error scanning port {port}: {e}")
            return port, 'closed'


def threaded_banner_grab(target, port, max_retries=3):
    """Enhanced banner grabbing with retries and protocol-specific handling"""
    probe_info = get_protocol_probe(port)

    for attempt in range(max_retries):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(probe_info['timeout'])
            s.connect((target, port))

            if probe_info['probe']:
                s.send(probe_info['probe'])

            banner = ""
            try:
                while True:
                    data = s.recv(1024).decode('utf-8', errors='ignore').strip()
                    if not data:
                        break
                    banner += data
            except socket.timeout:
                pass

            s.close()
            if banner:
                return port, banner

            if attempt < max_retries - 1:
                time.sleep(1)
                continue

        except Exception as e:
            if attempt < max_retries - 1:
                time.sleep(1)
                continue
            return port, f"Error after {max_retries} attempts: {str(e)}"

    return port, "No banner received"


def banner_grabbing(target, ports):
    """Perform banner grabbing on open ports"""
    print("\nPerforming banner grabbing...")
    banners = {}

    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_port = {
            executor.submit(threaded_banner_grab, target, port): port
            for port in ports
        }

        for future in concurrent.futures.as_completed(future_to_port):
            try:
                port, banner = future.result()
                banners[port] = banner
                print(f"[+] Banner for port {port}: {banner}")
            except Exception as e:
                port = future_to_port[future]
                banners[port] = f"Error: {str(e)}"
                print(f"[-] Could not grab banner for port {port}: {e}")

    return banners


def detect_service_version(banner):
    """Attempt to identify service version from banner"""
    version_patterns = {
        'ssh': r'SSH-\d+\.\d+-([\w._-]+)',
        'http': r'Server: ([\w._-]+)',
        'ftp': r'([\w._-]+) FTP',
        'smtp': r'([\w._-]+) ESMTP',
        'mysql': r'([\d.]+)-MariaDB|MySQL\s+([\d.]+)'
    }

    try:
        for service, pattern in version_patterns.items():
            match = re.search(pattern, banner)
            if match:
                return match.group(1)
    except:
        pass
    return "Unknown Version"


def scan_ports(target, start_port, end_port):
    """Perform port scanning with progress tracking"""
    print(f"\nScanning {target} for open ports...")
    total_ports = end_port - start_port + 1
    ports_scanned = 0
    open_ports = []

    port_scanner = PortScanner()

    def update_progress(progress):
        bar_length = 50
        filled = int(bar_length * progress)
        bar = '=' * filled + '-' * (bar_length - filled)
        percent = int(progress * 100)
        print(f'\rProgress: [{bar}] {percent}%', end='')

    with ThreadPoolExecutor(max_workers=50) as executor:
        future_to_port = {
            executor.submit(port_scanner.scan_port, target, port): port
            for port in range(start_port, end_port + 1)
        }

        for future in concurrent.futures.as_completed(future_to_port):
            ports_scanned += 1
            progress = ports_scanned / total_ports
            update_progress(progress)

            try:
                port, state = future.result()
                if state == 'open':
                    open_ports.append(port)
            except Exception as e:
                print(f"\nError scanning port {future_to_port[future]}: {e}")

    print(f"\nScan completed! Found {len(open_ports)} open ports")
    return open_ports


def nmap_logger(ports, target, start_port, end_port, scan_start_time):
    """Log scan results to JSON file"""
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_filename = f"scan_{target}_{timestamp}.json"

    scan_duration = (datetime.now() - scan_start_time).total_seconds()

    try:
        hostname = socket.gethostbyaddr(target)[0]
    except:
        hostname = "Unable to resolve"

    banners = banner_grabbing(target, ports)

    scan_data = {
        "metadata": {
            "scan_time": timestamp,
            "scan_duration_seconds": scan_duration,
            "target_ip": target,
            "target_hostname": hostname,
            "ports_scanned": {
                "start": start_port,
                "end": end_port,
                "total": end_port - start_port + 1
            },
            "open_ports_count": len(ports)
        },
        "open_ports": []
    }

    for port in ports:
        banner = banners.get(port, "No banner")
        service_name = get_service_name(port)
        version = detect_service_version(banner)

        port_data = {
            "port_number": port,
            "service": service_name,
            "version": version,
            "banner": banner,
            "scan_time": datetime.now().strftime("%H:%M:%S")
        }
        scan_data["open_ports"].append(port_data)

    try:
        with open(log_filename, 'w') as f:
            json.dump(scan_data, f, indent=4)
        print(f"\n[+] Scan results saved to {log_filename}")
    except Exception as e:
        print(f"\n[-] Failed to save scan results: {e}")


if __name__ == "__main__":
    check_root()
    target = get_target_ip()
    start_port, end_port = get_port_range()

    scan_start_time = datetime.now()
    print(f"\nStarting scan at: {scan_start_time.strftime('%Y-%m-%d %H:%M:%S')}")

    open_ports = scan_ports(target, start_port, end_port)

    if open_ports:
        nmap_logger(open_ports, target, start_port, end_port, scan_start_time)
    else:
        print("\nNo open ports found.")
