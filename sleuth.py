#!/usr/bin/env python3
import argparse
import sys
import socket
import concurrent.futures
from datetime import datetime

# --- Configuration ---
VERSION = "1.2.0"
TOOL_NAME = "Cyber Sleuth Toolkit"
MAX_THREADS = 50  # Number of simultaneous threads

def banner():
    print(f"""
    ===========================================
      {TOOL_NAME} v{VERSION}
      created by Liberty Kondo
    ===========================================
    """)

def check_port(target_ip, port):
    """Worker function: Checks a single port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target_ip, port))
        
        if result == 0:
            try:
                # Grab Banner
                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                banner = sock.recv(1024).decode().strip()
                return port, True, banner[:50] # Truncated
            except:
                return port, True, "No Banner"
        sock.close()
    except:
        pass
    return port, False, None

def scan_target(target, ports):
    """Threaded Port Scanner"""
    print(f"[*] Starting Threaded Scan on {target}...")
    start_time = datetime.now()
    
    try:
        target_ip = socket.gethostbyname(target)
        print(f"[*] IP Address: {target_ip}")
        print(f"[*] Threads: {MAX_THREADS}\n")
        
        # Using ThreadPoolExecutor for concurrency
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            # Create a dictionary of future tasks
            future_to_port = {executor.submit(check_port, target_ip, port): port for port in ports}
            
            for future in concurrent.futures.as_completed(future_to_port):
                port, is_open, banner_data = future.result()
                if is_open:
                    if banner_data:
                        print(f"[+] Port {port}: OPEN -> {banner_data}")
                    else:
                        print(f"[+] Port {port}: OPEN")
            
    except socket.gaierror:
        print("\n[!] Hostname could not be resolved.")
    except KeyboardInterrupt:
        print("\n[!] Scan stopped by user.")
        sys.exit()

    print(f"\n[*] Scan completed in {datetime.now() - start_time}")

def main():
    banner()
    parser = argparse.ArgumentParser(description="A Python-based security toolkit.")
    parser.add_argument("-t", "--target", help="Target IP or Hostname", required=True)
    parser.add_argument("-p", "--ports", help="Ports to scan (comma separated) or range (e.g. 20-100)", default="20-100")
    
    args = parser.parse_args()
    
    # Parse ports (Now supports ranges like "20-100")
    port_list = []
    if '-' in args.ports:
        start, end = map(int, args.ports.split('-'))
        port_list = range(start, end + 1)
    else:
        port_list = [int(p) for p in args.ports.split(',')]

    scan_target(args.target, port_list)

if __name__ == "__main__":
    main()

