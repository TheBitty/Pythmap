import nmap
from scapy.all import *
from datetime import datetime
import json
import socket


def scan_ports(target):
    nm = nmap.PortScanner()
    print(f"Scanning {target} for open ports...")
    nm.scan(target, arguments='-sT -T4')

    OpenPorts = []
    for host in nm.all_hosts():
        print(f"\nHost: {host} ({nm[host].hostname()})")
        print(f"State: {nm[host].state()}")

        for proto in nm[host].all_protocols():
            print(f"\nProtocol: {proto}")
            ports = nm[host][proto].keys()
            for port in ports:
                state = nm[host][proto][port]['state']
                print(f"Port: {port}, State: {state}")
                if state == "open":
                    OpenPorts.append(port)

    return OpenPorts


def banner_grabbing(target, ports):
    print("\nPerforming banner grabbing...")
    banners = {}  # Store banners for logging
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((target, port))

            if port == 80:
                s.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")

            banner = s.recv(1024).decode().strip()
            banners[port] = banner  # Save banner for logging
            print(f"[+] Banner for port {port}: {banner}")
            s.close()
        except Exception as e:
            banners[port] = f"Error: {str(e)}"  # Save error for logging
            print(f"[-] Could not grab banner for port {port}: {e}")
    return banners

def enhanced_banner_grabbing(ports):
    common_ports = {        80: [
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
    target = input("Enter target IP: ")
    open_ports = scan_ports(target)

    if open_ports:
        nmap_logger(open_ports, target)