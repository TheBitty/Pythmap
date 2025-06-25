from datetime import datetime
import json
import socket
import os
import sys
import ipaddress
import re
import concurrent
import math
import logging
import logging.handlers
from concurrent.futures import ThreadPoolExecutor
import asyncio
import csv
import xml.etree.ElementTree as ET
from typing import List, Dict, Tuple, Optional, Union
import time
import threading
import subprocess
import venv

# Global logger variable
logger = None


def setup_virtual_environment():
    """Setup and activate virtual environment"""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    venv_dir = os.path.join(script_dir, "venv")
    
    # Check if already in virtual environment
    if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
        print("[+] Already running in virtual environment")
        return True
    
    # Check if venv directory exists
    if not os.path.exists(venv_dir):
        print("[+] Creating virtual environment...")
        try:
            venv.create(venv_dir, with_pip=True)
            print(f"[+] Virtual environment created at: {venv_dir}")
        except Exception as e:
            print(f"[-] Failed to create virtual environment: {e}")
            return False
    
    # Activate virtual environment by restarting with venv python
    if os.name == 'nt':  # Windows
        venv_python = os.path.join(venv_dir, "Scripts", "python.exe")
        venv_pip = os.path.join(venv_dir, "Scripts", "pip.exe")
    else:  # Unix/Linux
        venv_python = os.path.join(venv_dir, "bin", "python")
        venv_pip = os.path.join(venv_dir, "bin", "pip")
    
    if not os.path.exists(venv_python):
        print("[-] Virtual environment python not found")
        return False
    
    # Install required packages if not already installed
    required_packages = ["python-nmap", "scapy"]
    for package in required_packages:
        try:
            __import__(package.replace("-", "_"))
        except ImportError:
            print(f"[+] Installing {package} in virtual environment...")
            try:
                subprocess.check_call([venv_pip, "install", package], 
                                    stdout=subprocess.DEVNULL, 
                                    stderr=subprocess.DEVNULL)
                print(f"[+] {package} installed successfully")
            except subprocess.CalledProcessError as e:
                print(f"[-] Failed to install {package}: {e}")
    
    # If we're not in the venv python, restart with it
    if sys.executable != venv_python:
        print(f"[+] Activating virtual environment and restarting...")
        try:
            os.execv(venv_python, [venv_python] + sys.argv)
        except Exception as e:
            print(f"[-] Failed to restart with virtual environment: {e}")
            return False
    
    return True


def print_banner():
    """Display ASCII art banner for PythMap"""
    banner = """

 ██████╗ ██╗   ██╗████████╗██╗  ██╗███╗   ███╗ █████╗ ██████╗ 
 ██╔══██╗╚██╗ ██╔╝╚══██╔══╝██║  ██║████╗ ████║██╔══██╗██╔══██╗
 ██████╔╝ ╚████╔╝    ██║   ███████║██╔████╔██║███████║██████╔╝
 ██╔═══╝   ╚██╔╝     ██║   ██╔══██║██║╚██╔╝██║██╔══██║██╔═══╝ 
 ██║        ██║      ██║   ██║  ██║██║ ╚═╝ ██║██║  ██║██║     
 ╚═╝        ╚═╝      ╚═╝   ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     
                                                               
    An Advanced Network Port Scanner & Security Assessment Tool    
                     Created By TheBitty               

"""
    print(banner)


def setup_logging():
    """Configure logging for the application"""
    # Create logger
    logger = logging.getLogger('portscan')
    logger.setLevel(logging.INFO)

    # Create console handler (this will always work)
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console_format = logging.Formatter('%(message)s')
    console.setFormatter(console_format)
    logger.addHandler(console)

    # Try to create a file handler, but gracefully handle permission errors
    try:
        # Try current directory first (more likely to have permissions)
        script_dir = os.path.dirname(os.path.abspath(__file__))
        log_folder = os.path.join(script_dir, "logs")

        # Try to create the directory
        os.makedirs(log_folder, exist_ok=True)

        # Create file handler for detailed logs
        log_file = os.path.join(log_folder, f"scan_log_{datetime.now().strftime('%Y-%m-%d')}.log")
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=10485760, backupCount=5)
        file_handler.setLevel(logging.DEBUG)
        file_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(file_format)
        logger.addHandler(file_handler)

        print(f"Log file created at: {log_file}")
    except PermissionError:
        print("Warning: Could not create log file due to permission error.")
        print("Continuing with console logging only.")
    except Exception as e:
        print(f"Warning: Could not set up file logging: {e}")
        print("Continuing with console logging only.")

    return logger


def check_root():
    """Check and obtain root privileges"""
    # First check if we're on a platform where we can check for root
    if hasattr(os, 'geteuid'):
        if os.geteuid() != 0:
            print("\nPlease run as root")
            print("\nAttempting to run as root...")
            try:
                # Get the full path to the current script
                script_path = os.path.abspath(sys.argv[0])
                # Use sys.executable to get the correct Python interpreter path
                interpreter = sys.executable
                # Execute: sudo [current-python] [full-script-path] [all-arguments]
                os.execvp('sudo', ['sudo', interpreter, script_path] + sys.argv[1:])
            except PermissionError:
                print("\n[-] Failed to obtain root privileges: Permission denied")
                print("\nExiting...please use the sudo command to run the script as root")
                sys.exit(1)
            except FileNotFoundError:
                print("\n[-] Failed to obtain root privileges: sudo command not found")
                print("\nExiting...please install sudo or run the script as root")
                sys.exit(1)
            except Exception as e:
                print(f"\n[-] Failed to obtain root privileges: {e}")
                print("\nExiting...please use the sudo command to run the script as root")
                sys.exit(1)  # scans are needed for root
    else:
        # On Windows or other platforms where geteuid isn't available
        print("\nWarning: Cannot check for root/admin privileges on this platform.")
        print("Some scanning features may not work without admin privileges.")
        print("Please make sure you're running this script with administrator rights.")

        # On Windows, we could try to check for admin, but for now just warn the user
        if os.name == 'nt':
            print("On Windows, right-click the command prompt and select 'Run as administrator'")

        # Continue anyway
        return


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
            logger.warning(f"[-] Invalid IP address: {target}")
            logger.info("[!] Please enter a valid IP (e.g., 192.168.1.1)")
            continue


def get_port_range():
    """Get custom port range from user"""
    while True:
        try:
            logger.info("\nSelect port range to scan:")
            logger.info("1. Common ports (1-1024)")
            logger.info("2. Extended range (1-5000)")
            logger.info("3. Full range (1-65535)")
            logger.info("4. Custom range")

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
                    logger.warning("Invalid port range!")
            else:
                logger.warning("Invalid choice!")
        except ValueError:
            logger.warning("Please enter valid numbers!")


def scan_ports(target, start_port, end_port):
    """Perform port scanning with better progress reporting"""
    logger.info(f"\nScanning {target} for open ports...")
    
    try:
        import nmap
    except ImportError:
        logger.error("python-nmap package not found. Please run the script again to auto-install dependencies.")
        return []
    
    nm = nmap.PortScanner()
    open_ports = []

    # Initialize progress bar variables outside the try block
    bar_length = 50
    ports_processed = 0
    total_ports = end_port - start_port + 1

    try:
        # Divide the port range into chunks for better progress reporting
        chunk_size = 1000
        total_chunks = math.ceil(total_ports / chunk_size)

        for chunk in range(total_chunks):
            chunk_start = start_port + chunk * chunk_size
            chunk_end = min(chunk_start + chunk_size - 1, end_port)

            # Show progress based on ports processed, not just chunks
            progress = ports_processed / total_ports
            filled = int(bar_length * progress)
            bar = '=' * filled + '-' * (bar_length - filled)
            percent = int(progress * 100)
            print(f'\rProgress: [{bar}] {percent}% (scanning ports {chunk_start}-{chunk_end})', end='')

            # Scan this chunk
            chunk_range = f"{chunk_start}-{chunk_end}"
            try:
                nm.scan(target, ports=chunk_range, arguments='-sS -T4 -n --min-rate=1000')

                # Process results for this chunk
                if target in nm.all_hosts():
                    for port in range(chunk_start, chunk_end + 1):
                        try:
                            if nm[target].has_tcp(port) and nm[target]['tcp'][port]['state'] == 'open':
                                logger.info(f"\nFound open port: {port}")
                                open_ports.append(port)
                        except KeyError:
                            # Specifically handling the case when port isn't in the results
                            pass
                        except Exception as e:
                            logger.error(f"\nUnexpected error checking port {port}: {str(e)}")
                        finally:
                            # Increment counter regardless of result to ensure accurate progress
                            ports_processed += 1
                else:
                    # If target wasn't in results, still count these ports as processed
                    ports_processed += (chunk_end - chunk_start + 1)
            except Exception as e:
                logger.error(f"\nError scanning chunk {chunk_start}-{chunk_end}: {e}")
                # Still count these ports as processed even if scanning failed
                ports_processed += (chunk_end - chunk_start + 1)

            # Update progress after each chunk
            progress = ports_processed / total_ports
            filled = int(bar_length * progress)
            bar = '=' * filled + '-' * (bar_length - filled)
            percent = int(progress * 100)
            print(f'\rProgress: [{bar}] {percent}% (processed {ports_processed} ports)', end='')

        # Complete the progress bar
        print(f'\rProgress: [{"=" * bar_length}] 100%')
        logger.info(f"\nScan completed! Found {len(open_ports)} open ports")

    except Exception as e:
        logger.error(f"\nNmap scanning error: {e}")
        # Ensure we still show a complete progress bar in case of error
        print(f'\rProgress: [{"=" * bar_length}] 100% (scan terminated due to error)')
    except socket.gaierror:
        logger.error(f"\nError: Could not resolve hostname {target}")
        print(f'\rProgress: [{"=" * bar_length}] 100% (scan terminated due to error)')
    except PermissionError:
        logger.error(f"\nError: Permission denied - Make sure you're running with elevated privileges")
        print(f'\rProgress: [{"=" * bar_length}] 100% (scan terminated due to error)')
    except Exception as e:
        logger.error(f"\nUnexpected error during scan: {e}")
        print(f'\rProgress: [{"=" * bar_length}] 100% (scan terminated due to error)')

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
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        465: "SMTPS",
        587: "SMTP Submission",
        993: "IMAPS",
        995: "POP3S",
        1433: "MSSQL",
        1521: "Oracle",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        8080: "HTTP-Proxy",
        8443: "HTTPS-Alt",
        27017: "MongoDB",
        6379: "Redis",
        5900: "VNC",
        5432: "PostgreSQL",
        1521: "Oracle",
        1433: "MSSQL",
        389: "LDAP",
        636: "LDAPS",
        161: "SNMP",
        162: "SNMP-Trap",
        69: "TFTP",
        123: "NTP",
        135: "RPC",
        139: "NetBIOS",
        445: "SMB",
        993: "IMAPS",
        995: "POP3S",
        465: "SMTPS",
        587: "SMTP-Sub",
        143: "IMAP",
        110: "POP3",
        25: "SMTP",
        53: "DNS",
        67: "DHCP",
        68: "DHCP-Client"
    }
    return common_ports.get(port, "Unknown")


def threaded_banner_grab(target, port):
    """Perform banner grabbing for a single port with improved protocol handling"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((target, port))

        # Define port-specific probes
        port_probes = {
            21: b"USER anonymous\r\n",
            22: b"SSH-2.0-OpenSSH_8.2p1\r\n",
            25: b"EHLO scan.local\r\n",
            80: b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n",
            110: b"USER test\r\n",
            143: b"A1 CAPABILITY\r\n",
            443: None,  # HTTPS requires SSL/TLS - handle specially
            3306: b"\x00\x00\x00\x00\x00",  # MySQL probe
            5432: b"\x00\x00\x00\x08\x04\xd2\x16\x2f",  # PostgreSQL probe
            8080: b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n",
            8443: None  # HTTPS requires SSL/TLS - handle specially
        }

        # SSL/TLS ports that should be handled specially
        ssl_ports = {443, 465, 636, 993, 995, 8443}

        if port in ssl_ports:
            return port, f"SSL/TLS Service (port {port})"

        # Send appropriate probe or default to empty string
        probe = port_probes.get(port, b"")
        if probe:
            s.send(probe)

        # Safer banner receiving with graceful handling of connection issues
        try:
            banner_data = s.recv(1024)
            banner = banner_data.decode('utf-8', errors='ignore').strip()
        except socket.timeout:
            banner = "Connection timed out while receiving data"
        except ConnectionResetError:
            banner = "Connection reset by peer"
        except Exception as e:
            banner = f"Error receiving banner: {str(e)}"

        s.close()
        return port, banner
    except ConnectionRefusedError:
        return port, "Error: Connection refused"
    except socket.timeout:
        return port, "Error: Connection timeout"
    except OSError as e:
        return port, f"Error: Network error - {str(e)}"
    except Exception as e:
        return port, f"Error: {str(e)}"


def banner_grabbing(target, ports):
    """Perform parallel banner grabbing with improved error logging"""
    logger.info("\nPerforming banner grabbing...")
    banners = {}

    # Create a separate error counter to reduce console clutter
    error_count = 0
    error_types = {}

    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_port = {
            executor.submit(threaded_banner_grab, target, port): port
            for port in ports
        }

        for future in concurrent.futures.as_completed(future_to_port):
            try:
                port, banner = future.result()
                banners[port] = banner

                # Check if this is an error banner and handle accordingly
                if banner.startswith("Error:"):
                    error_count += 1
                    error_type = banner.split(":", 1)[1].strip()
                    # Count error types for summary
                    error_types[error_type] = error_types.get(error_type, 0) + 1
                    # Log error to debug log but don't show in main output
                    logger.debug(f"[-] Banner error for port {port}: {banner}")
                else:
                    # Only show successful banner grabs in main output
                    logger.info(f"[+] Banner for port {port}: {banner}")
            except Exception as e:
                error_count += 1
                error_type = str(e)
                error_types[error_type] = error_types.get(error_type, 0) + 1
                logger.debug(f"[-] Exception in banner grabbing for port {future_to_port[future]}: {e}")

        # Provide a summary of errors if any occurred
        if error_count > 0:
            logger.info(f"\n[!] Banner grabbing completed with {error_count} errors")
            for error_type, count in error_types.items():
                logger.debug(f"    - {count} x {error_type}")
            logger.info("[!] Run with debug logging enabled to see detailed error information")

    return banners


def detect_service_version(banner):
    """Extract version information from banner with improved multi-line handling"""
    version_patterns = {
        'ssh': [r'SSH-\d+\.\d+-([\w._-]+)', r'OpenSSH[_-]([\d.]+)'],
        'http': [r'Server:\s+([\w._/-]+)', r'Apache/([\d.]+)', r'nginx/([\d.]+)', r'Microsoft-IIS/([\d.]+)'],
        'ftp': [r'([\w._-]+) FTP', r'FTP server \(Version ([\w._-]+)\)'],
        'smtp': [r'([\w._-]+) ESMTP', r'([\w._-]+) Mail Service'],
        'mysql': [r'([\d.]+)-MariaDB', r'MySQL\s+([\d.]+)', r'mysql_native_password'],
        'telnet': [r'([\w._-]+) telnetd'],
        'pop3': [r'POP3 Server ([\w._-]+)'],
        'imap': [r'IMAP4rev1 ([\w._-]+)'],
        'generic': [r'version[\s:]+([\w._-]+)', r'([\d.]+\d)']  # Generic patterns as fallback
    }

    try:
        # Split banner into lines to handle multi-line responses
        banner_lines = banner.splitlines()

        # Try to match service-specific patterns first, line by line
        for line in banner_lines:
            for service, patterns in version_patterns.items():
                for pattern in patterns:
                    match = re.search(pattern, line, re.IGNORECASE)
                    if match:
                        return match.group(1)

        # If no match in line-by-line search, try the whole banner
        for service, patterns in version_patterns.items():
            for pattern in patterns:
                match = re.search(pattern, banner, re.IGNORECASE)
                if match:
                    return match.group(1)

        # If still no match, check for common version patterns in the whole banner
        for pattern in version_patterns['generic']:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1)

    except re.error as e:
        logger.debug(f"Regex error in service detection: {e}")
    except Exception as e:
        logger.debug(f"Error detecting version: {e}")

    return "Unknown Version"


def vuln_scan(target, ports):
    """Perform vulnerability scan using nmap NSE scripts"""
    logger.info("\nPerforming vulnerability scan...")
    
    try:
        import nmap
    except ImportError:
        logger.error("python-nmap package not found. Skipping vulnerability scan.")
        return {}
    
    nm = nmap.PortScanner()

    if not ports:
        logger.warning("No open ports to scan for vulnerabilities")
        return {}

    port_list = ','.join(map(str, ports))

    vuln_results = {}
    try:
        logger.info("Running vulnerability scripts (this may take a while)...")
        nm.scan(
            target,
            ports=port_list,
            arguments='--script vuln,exploit,auth,default,version -sV'
        )

        if target in nm.all_hosts():
            for port in ports:
                try:
                    if nm[target].has_tcp(port):
                        port_info = nm[target]['tcp'][port]
                        scripts_results = port_info.get('script', {})

                        if scripts_results:
                            vuln_results[port] = {
                                'service': port_info.get('name', 'unknown'),
                                'version': port_info.get('version', 'unknown'),
                                'vulnerabilities': scripts_results
                            }
                            logger.info(f"\n[+] Found potential vulnerabilities on port {port}:")
                            for script_name, result in scripts_results.items():
                                logger.info(f"  - {script_name}: {result}")
                except KeyError:
                    logger.debug(f"Port {port} not found in scan results")
                except Exception as e:
                    logger.error(f"Error processing vulnerability results for port {port}: {e}")

    except Exception as e:
        logger.error(f"\nNmap vulnerability scanning error: {e}")
    except Exception as e:
        logger.error(f"\nError during vulnerability scan: {e}")

    return vuln_results


def nmap_logger(ports, target, start_port, end_port, scan_start_time):
    """Log scan results to JSON file"""
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_folder = "logs"  # Specify the folder name
    os.makedirs(log_folder, exist_ok=True)  # Create the folder if it doesn't exist
    log_filename = os.path.join(log_folder, f"scan_{target}_{timestamp}.json")

    scan_duration = (datetime.now() - scan_start_time).total_seconds()

    try:
        hostname = socket.gethostbyaddr(target)[0]
    except socket.herror:
        hostname = "Unable to resolve"
    except Exception as e:
        hostname = f"Error resolving: {str(e)}"

    logger.info("\nGathering additional information...")
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
        logger.info(f"\n[+] Scan results saved to {log_filename}")
        os.chmod(log_filename, 0o644)
    except PermissionError:
        logger.error(f"\n[-] Failed to save scan results: Permission denied for {log_filename}")
    except Exception as e:
        logger.error(f"\n[-] Failed to save scan results: {e}")


def print_summary(target, open_ports, scan_start_time):
    """Print a summary of the scan results"""
    scan_duration = (datetime.now() - scan_start_time).total_seconds()

    logger.info("\n" + "=" * 60)
    logger.info(f"SCAN SUMMARY FOR {target}")
    logger.info("=" * 60)
    logger.info(f"Scan started at: {scan_start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"Scan duration: {scan_duration:.2f} seconds")
    logger.info(f"Open ports found: {len(open_ports)}")

    if open_ports:
        logger.info("\nOpen Ports:")
        for port in open_ports:
            service = get_service_name(port)
            logger.info(f"  - {port}/tcp: {service}")

    logger.info("=" * 60)


def main():
    """Entry point for the pythmap scanner"""
    global logger
    
    # Setup virtual environment first
    print("Initializing PythMap Scanner...")
    if not setup_virtual_environment():
        print("[-] Failed to setup virtual environment, continuing anyway...")
    
    # Import required packages after venv setup
    try:
        import nmap
        print("[+] Required packages loaded successfully")
    except ImportError as e:
        print(f"[-] Failed to import required packages: {e}")
        print("[!] Some functionality may be limited")
    
    # Set up logging
    try:
        logger = setup_logging()
    except Exception as e:
        print(f"Error setting up logging: {e}")
        print("Continuing with basic console output.")
        # Create a basic logger that just prints to console
        logger = logging.getLogger('portscan')
        logger.setLevel(logging.INFO)
        console = logging.StreamHandler()
        logger.addHandler(console)

    try:
        # Check for root privileges
        check_root()
        
        # Clear screen after privilege escalation
        os.system('clear' if os.name != 'nt' else 'cls')
        
        # Show banner after screen clear
        print_banner()
        logger.info("Starting advanced port scanner")

        # Get target information
        target = get_target_ip()
        logger.info(f"Target selected: {target}")

        start_port, end_port = get_port_range()
        logger.info(f"Port range selected: {start_port}-{end_port}")

        # Start scanning
        scan_start_time = datetime.now()
        logger.info(f"\nStarting scan at: {scan_start_time.strftime('%Y-%m-%d %H:%M:%S')}")

        open_ports = scan_ports(target, start_port, end_port)

        if open_ports:
            print_summary(target, open_ports, scan_start_time)
            nmap_logger(open_ports, target, start_port, end_port, scan_start_time)
        else:
            logger.info("\nNo open ports found.")
    except KeyboardInterrupt:
        logger.info("\n\nScan interrupted by user. Exiting...")
    except Exception as e:
        logger.error(f"\nUnexpected error: {e}")
        # Only try to log debug info if logger has handlers
        if logger.handlers:
            logger.debug("Exception details:", exc_info=True)


if __name__ == "__main__":
    main()
