import nmap
from scapy.all import *
from datetime import datetime
import json
import socket
from concurrent.futures import ThreadPoolExecutor
import concurrent.futures
import ipaddress
import os
import sys

def check_root():
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
    try:
        # Remove any whitespace
        ip = ip.strip()

        # Basic IP format validation
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

def threaded_port_scan(target, port):
    """Individual port scan function for threading"""
    try:
        nm = nmap.PortScanner()
        nm.scan(target, str(port))
        if nm[target].has_tcp(port):
            state = nm[target]['tcp'][port]['state']
            if state == "open":
                return port, True
        return port, False
    except Exception as e:
        print(f"Error scanning port {port}: {e}")
        return port, False

def scan_ports(target):
    print(f"Scanning {target} for open ports...")
    OpenPorts = []

    # Using ThreadPoolExecutor for parallel port scanning
    with ThreadPoolExecutor(max_workers=50) as executor:
        # Create a list of futures for port scans
        port_range = range(1, 1025)  # Scan first 1024 ports
        future_to_port = {
            executor.submit(threaded_port_scan, target, port): port
            for port in port_range
        }

        # Process results as they complete
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            try:
                port, is_open = future.result()
                if is_open:
                    print(f"Port {port} is open")
                    OpenPorts.append(port)
            except Exception as e:
                print(f"Port {port} generated an exception: {e}")

    return OpenPorts

def threaded_banner_grab(target, port):
    """Individual banner grab function for threading"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((target, port))

        # Send appropriate probe based on port
        if port == 80:
            s.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
        elif port == 21:
            pass  # FTP servers usually send banner automatically
        elif port == 22:
            pass  # SSH servers usually send banner automatically

        banner = s.recv(1024).decode().strip()
        s.close()
        return port, banner
    except Exception as e:
        return port, f"Error: {str(e)}"

def banner_grabbing(target, ports):
    print("\nPerforming banner grabbing...")
    banners = {}

    # Using ThreadPoolExecutor for parallel banner grabbing
    with ThreadPoolExecutor(max_workers=10) as executor:
        # Create futures for banner grabs
        future_to_port = {
            executor.submit(threaded_banner_grab, target, port): port
            for port in ports
        }

        # Process results as they complete
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            try:
                port, banner = future.result()
                banners[port] = banner
                print(f"[+] Banner for port {port}: {banner}")
            except Exception as e:
                banners[port] = f"Error: {str(e)}"
                print(f"[-] Could not grab banner for port {port}: {e}")

    return banners

def enhanced_banner_grabbing(target, ports):
    common_probes = {
        80: [
            b"GET / HTTP/1.1\r\n\r\n",
            b"HEAD / HTTP/1.1\r\n\r\n"
        ],
        443: [
            b"\x16\x03\x01\x00\x01\x01"  # SSL/TLS probe
        ],
        21: [
            b"USER anonymous\r\n"
        ]
    }
    # Future implementation for enhanced probing
    pass

def nmap_logger(ports, target):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_filename = f"scan_{target}_{timestamp}.json"

    banners = banner_grabbing(target, ports)

    scan_data = {
        "scan_time": timestamp,
        "target": target,
        "open_ports": [],
    }

    for port in ports:
        port_data = {
            "port_number": port,
            "banner": banners.get(port, "No banner"),
            "service": {
                21: "FTP",
                22: "SSH",
                23: "Telnet",
                25: "SMTP",
                53: "DNS",
                80: "HTTP",
                443: "HTTPS",
                3306: "MySQL",
                3389: "RDP"
            }.get(port, "Unknown")
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
    open_ports = scan_ports(target)

    if open_ports:
        nmap_logger(open_ports, target)
