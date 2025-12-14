import socket
import sys
import argparse
import threading
from datetime import datetime

# Global counter for open ports
OPEN_PORTS_COUNT = 0
# Semaphore to limit the number of active threads (e.g., max 100 simultaneous threads)
THREAT_SEMAPHORE = threading.BoundedSemaphore(value=100)


# 1. Port Scanning Function
def scan_port(target_ip, port):
    # Attempts to connect to a specific port on a host.
    global OPEN_PORTS_COUNT

    # Acquire the semaphore to run this thread
    THREAT_SEMAPHORE.acquire()

    try:
        # AF_INET is for IPv4; SOCK_STREAM is for TCP
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1) # Timeout is crucial for threads

        result = s.connect_ex((target_ip, port))
        s.close()

        if result == 0:
            try:
                service = socket.getservbyport(port)
            except OSError:
                service = "unknown service"
        
            print(f"\r [+] Port {port:<5} is OPEN | Service: {service}\n")
            OPEN_PORTS_COUNT += 1
    except Exception as e:
        # Handle exceptions within the thread
        pass
    finally:
        # Release the semaphore after finishing
        THREAT_SEMAPHORE.release()
    
# 2. Argument Parsing and Main Execution

def parse_arguments():
    # Configures and parses command-line arguments.
    parser = argparse.ArgumentParser(
        description="Simple multi-threaded TCP Port Scanner"
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
    global OPEN_PORTS_COUNT
    threads = []
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
    
    # Scanning loops with exit
    try: 
        for port in range(start_port, end_port + 1):
            # Create a new thread for each port scan
            t = threading.Thread(target=scan_port, args=(target_ip, port))
            threads.append(t)
            t.start()
        
        # Wait for all threads to finish before exiting main
        for t in threads:
            t.join()
    
    except KeyboardInterrupt:
        sys.stdout.write('\r' + ' ' * 50 + '\r') 
        print("[*] Scan interrupted by user (Ctrl+C).")
        # Note: Threading makes a clean exit harder, but the join() helps wait for running ones
        
    # Clear the scanning progress line before printing the final message
    sys.stdout.write('\r' + ' ' * 50 + '\r') 
    
    print("\n" + "-" * 50)
    print(f"Scan finished. Total open ports found: {OPEN_PORTS_COUNT}")
    print("-" * 50)


if __name__ == '__main__':
    main()