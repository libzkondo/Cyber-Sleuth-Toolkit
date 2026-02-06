#!/usr/bin/env python3
import argparse
import sys
import socket
from datetime import datetime

# --- Configuration ---
VERSION = "1.0.0"
TOOL_NAME = "Cyber Sleuth Toolkit"

def banner():
    print(f"""
    ===========================================
      {TOOL_NAME} v{VERSION}
      created by Liberty Kondo
    ===========================================
    """)

def scan_target(target, ports):
    """Basic TCP Connect Scan"""
    print(f"[*] Starting scan on {target}...")
    start_time = datetime.now()
    
    try:
        # Resolve target IP
        target_ip = socket.gethostbyname(target)
        print(f"[*] IP Address: {target_ip}")
        
        # Scan ports
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                print(f"[+] Port {port}: OPEN")
            sock.close()
            
    except socket.gaierror:
        print("\n[!] Hostname could not be resolved.")
    except socket.error:
        print("\n[!] Could not connect to server.")
    except KeyboardInterrupt:
        print("\n[!] Scan stopped by user.")
        sys.exit()

    print(f"[*] Scan completed in {datetime.now() - start_time}")

def main():
    banner()
    
    parser = argparse.ArgumentParser(description="A Python-based security toolkit.")
    
    # Add arguments
    parser.add_argument("-t", "--target", help="Target IP or Hostname", required=True)
    parser.add_argument("-p", "--ports", help="Ports to scan (comma separated, e.g., 21,22,80)", default="80")
    
    args = parser.parse_args()
    
    # Parse port list
    try:
        port_list = [int(p) for p in args.ports.split(',')]
    except ValueError:
        print("[!] Error: Ports must be integers separated by commas.")
        sys.exit(1)

    # Execute Mode
    scan_target(args.target, port_list)

if __name__ == "__main__":
    main()

