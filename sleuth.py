#!/usr/bin/env python3
import argparse
import sys
import socket
import concurrent.futures
from datetime import datetime

# --- Configuration ---
VERSION = "1.3.0"
TOOL_NAME = "Cyber Sleuth Toolkit"
MAX_THREADS = 50

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
                return port, True, banner
            except:
                return port, True, None
        sock.close()
    except:
        pass
    return port, False, None

def save_to_file(filename, data):
    """Appends a single line to the output file."""
    try:
        with open(filename, "a") as f:
            f.write(data + "\n")
    except Exception as e:
        print(f"[!] Error writing to file: {e}")

def scan_target(target, ports, output_file=None):
    """Threaded Port Scanner with File Output"""
    print(f"[*] Starting Threaded Scan on {target}...")
    
    start_time = datetime.now()
    
    # If saving to file, write a header first
    if output_file:
        save_to_file(output_file, f"--- Scan Report for {target} [{start_time}] ---")

    try:
        target_ip = socket.gethostbyname(target)
        print(f"[*] IP Address: {target_ip}")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            future_to_port = {executor.submit(check_port, target_ip, port): port for port in ports}
            
            for future in concurrent.futures.as_completed(future_to_port):
                port, is_open, banner_data = future.result()
                
                if is_open:
                    # Format the output string
                    if banner_data:
                        result_str = f"[+] Port {port}: OPEN -> {banner_data[:50]}"
                    else:
                        result_str = f"[+] Port {port}: OPEN"
                    
                    # 1. Print to screen
                    print(result_str)
                    
                    # 2. Save to file (if requested)
                    if output_file:
                        save_to_file(output_file, result_str)
            
    except socket.gaierror:
        print("\n[!] Hostname could not be resolved.")
    except KeyboardInterrupt:
        print("\n[!] Scan stopped by user.")
        sys.exit()

    end_time = datetime.now()
    duration = end_time - start_time
    print(f"\n[*] Scan completed in {duration}")
    
    if output_file:
        save_to_file(output_file, f"--- Completed in {duration} ---")
        print(f"[*] Results saved to {output_file}")

def main():
    banner()
    parser = argparse.ArgumentParser(description="A Python-based security toolkit.")
    parser.add_argument("-t", "--target", help="Target IP or Hostname", required=True)
    parser.add_argument("-p", "--ports", help="Ports (e.g. 20-100 or 80,443)", default="20-100")
    parser.add_argument("-o", "--output", help="Save results to a file")
    
    args = parser.parse_args()
    
    # Parse ports
    port_list = []
    if '-' in args.ports:
        start, end = map(int, args.ports.split('-'))
        port_list = range(start, end + 1)
    else:
        port_list = [int(p) for p in args.ports.split(',')]

    scan_target(args.target, port_list, args.output)

if __name__ == "__main__":
    main()

