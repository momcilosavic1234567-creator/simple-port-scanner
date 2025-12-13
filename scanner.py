import socket
import sys
from datetime import datetime

def scan_port(host, port):
    # AF_INET is for IPv4; SOCK_STREAM is for TCP
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)

    result = s.connect_ex((host, port))
    s.close()

    if result == 0:
        try:
            service = socket.getservbyport(port)
        except OSError:
            service = "unknown service"
        
        print(f"  [+] Port {port:<5} is OPEN | Service: {service}")
        return True
    return False

def main():
    # Configuration
    target_host = input("Enter the target IP or hostname (e.g., scanme.nmap.org): ")

    try:
        # Resolve hostname to an IP address
        target_ip = socket.gethostbyname(target_host)
    except socket.gaierror:
        print("\n[!] Hostname could not be resolved. Exiting.")
        sys.exit()
    
    print("-" * 50)
    print(f"Scanning target: {target_host} ({target_ip})")
    print(f"Time started: {datetime.now().strftime('%H:%M:%S')}")
    print("-" * 50)

    start_port = 20
    end_port = 1024
    
    open_count = 0
    
    
    try: 
        # Iterate through the port range
        for port in range(start_port, end_port + 1):
            if scan_port(target_ip, port):
                open_count += 1
    
    except KeyboardInterrupt:
        print("\n[*] Scan interrupted by user (Ctrl+C).")
        
        
    print("-" * 50)
    print(f"Scan finished. Total open ports found: {open_count}")
    print("-" * 50)

if __name__ == "__main__":
    main()
        