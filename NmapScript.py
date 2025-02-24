"""
Enhanced Network Scanner with Vulnerability Detection
Features:
- Port scanning with progress bar
- Service banner grabbing
- Vulnerability scanning
- JSON logging
"""

import nmap
from scapy.all import *
from datetime import datetime
import json
import socket
import os
import sys
import ipaddress
import re
import concurrent
from concurrent.futures import ThreadPoolExecutor


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


def scan_ports(target, start_port, end_port):
    """Perform port scanning with progress bar"""
    print(f"\nScanning {target} for open ports...")
    nm = nmap.PortScanner()
    open_ports = []

    def update_progress(progress):
        bar_length = 50
        filled = int(bar_length * progress)
        bar = '=' * filled + '-' * (bar_length - filled)
        percent = int(progress * 100)
        print(f'\rProgress: [{bar}] {percent}%', end='')

    try:
        # Scan entire range at once with aggressive timing
        port_range = f"{start_port}-{end_port}"
        nm.scan(target, ports=port_range, arguments='-sS -T4 -n --min-rate=1000')

        if target in nm.all_hosts():
            total_ports = end_port - start_port + 1
            ports_processed = 0

            for port in range(start_port, end_port + 1):
                ports_processed += 1
                progress = ports_processed / total_ports
                update_progress(progress)

                try:
                    if nm[target].has_tcp(port) and nm[target]['tcp'][port]['state'] == 'open':
                        print(f"\nFound open port: {port}")
                        open_ports.append(port)
                except:
                    continue

        print(f"\nScan completed! Found {len(open_ports)} open ports")

    except Exception as e:
        print(f"\nError during scan: {e}")

    return sorted(open_ports)

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


def threaded_banner_grab(target, port):
    """Perform banner grabbing for a single port"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((target, port))

        if port == 80 or port == 8080:
            s.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
        elif port == 443 or port == 8443:
            return port, "HTTPS Service"

        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        s.close()
        return port, banner
    except Exception as e:
        return port, f"Error: {str(e)}"


def banner_grabbing(target, ports):
    """Perform parallel banner grabbing"""
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
                print(f"[-] Error in banner grabbing: {e}")

    return banners


def detect_service_version(banner):
    """Extract version information from banner"""
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


def vuln_scan(target, ports):
    """Perform vulnerability scan using nmap NSE scripts"""
    print("\nPerforming vulnerability scan...")
    nm = nmap.PortScanner()

    if not ports:
        print("No open ports to scan for vulnerabilities")
        return {}

    port_list = ','.join(map(str, ports))

    vuln_results = {}
    try:
        print("Running vulnerability scripts (this may take a while)...")
        nm.scan(
            target,
            ports=port_list,
            arguments='--script vuln,exploit,auth,default,version -sV'
        )

        if target in nm.all_hosts():
            for port in ports:
                if nm[target].has_tcp(port):
                    port_info = nm[target]['tcp'][port]
                    scripts_results = port_info.get('script', {})

                    if scripts_results:
                        vuln_results[port] = {
                            'service': port_info.get('name', 'unknown'),
                            'version': port_info.get('version', 'unknown'),
                            'vulnerabilities': scripts_results
                        }
                        print(f"\n[+] Found potential vulnerabilities on port {port}:")
                        for script_name, result in scripts_results.items():
                            print(f"  - {script_name}: {result}")

    except Exception as e:
        print(f"\nError during vulnerability scan: {e}")

    return vuln_results


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
    vuln_results = vuln_scan(target, ports)

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
            "vulnerabilities": vuln_results.get(port, {}),
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
