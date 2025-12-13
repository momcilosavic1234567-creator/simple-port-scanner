import socket
import sys
import argparse
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
        
        sys.stdout.write(f"\r [+] Port {port:<5} is OPEN | Service: {service}\n")
        return True
    
    sys.stdout.write(f"\r [*] Scanning port {port}...")
    sys.stdout.flush()
    return False

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Simple TCP Port Scanner"
    )

    # Required argument for target host
    parser.add_argument(
        '-t', '--target',
        required=True,
        help='The target IP address or hostname to scan (e.g., scanme.nmap.org)'
    )
    # Optional arguments for port range
    parser.add_argument(
        '-p', '--ports',
        default='20-1024',
        help='The port range to scan (e.g., 1-100 or 80,443,1000-2000). Default is 20-1024.'
    )
    return parser.parse_args()

def main():
    # Configuration
    args = parse_arguments()
    target_host = args.target
    port_range_str = args.ports
    # Port Range Processing
    try:
        start_port, end_port = map(int, port_range_str.split('-'))
        if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port):
            raise ValueError
    except ValueError:
        print("\n[!] Invalid port range. USE 'START-END' (e.g., 1-100). Exiting.")
        sys.exit()

    # Target Resolution
    try:
        # Resolve hostname to an IP address
        target_ip = socket.gethostbyname(target_host)
    except socket.gaierror:
        print(f"\n[!] Hostname '{target_host}' could not be resolved. Exiting.")
        sys.exit()
    
    print("-" * 50)
    print(f"Scanning target: {target_host} ({target_ip})")
    print(f"Port: {start_port}-{end_port}")
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
        sys.stdout.write('\r' + ' ' * 50 + '\r')
        print("\n[*] Scan interrupted by user (Ctrl+C).")
        
        
    print("-" * 50)
    print(f"Scan finished. Total open ports found: {open_count}")
    print("-" * 50)

if __name__ == "__main__":
    main()
        