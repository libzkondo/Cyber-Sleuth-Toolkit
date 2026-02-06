#!/usr/bin/env python3
import argparse
import sys
import socket
from datetime import datetime

# --- Configuration ---
VERSION = "1.1.0"
TOOL_NAME = "Cyber Sleuth Toolkit"

def banner():
    print(f"""
    ===========================================
      {TOOL_NAME} v{VERSION}
      created by Liberty Kondo
    ===========================================
    """)

def get_service_banner(ip, port):
    """Attempts to grab a service banner from an open port."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, port))
        
        # Send a gentle nudge (some services wait for input)
        # HTTP requires a request line, others might just send data.
        if port == 80 or port == 8080:
            s.send(b'HEAD / HTTP/1.0\r\n\r\n')
        
        # Receive up to 1024 bytes
        banner_data = s.recv(1024).decode().strip()
        s.close()
        return banner_data
    except:
        return None

def scan_target(target, ports):
    """Scans for open ports and grabs banners."""
    print(f"[*] Starting scan on {target}...")
    start_time = datetime.now()
    
    try:
        target_ip = socket.gethostbyname(target)
        print(f"[*] IP Address: {target_ip}\n")
        
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target_ip, port))
            
            if result == 0:
                # Port is open!
                service_info = get_service_banner(target_ip, port)
                if service_info:
                    print(f"[+] Port {port}: OPEN -> {service_info[:50]}...") # Truncate long banners
                else:
                    print(f"[+] Port {port}: OPEN (No banner)")
            
            sock.close()
            
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
    parser.add_argument("-p", "--ports", help="Ports to scan (comma separated)", default="21,22,80,443")
    
    args = parser.parse_args()
    
    try:
        port_list = [int(p) for p in args.ports.split(',')]
    except ValueError:
        print("[!] Error: Ports must be integers.")
        sys.exit(1)

    scan_target(args.target, port_list)

if __name__ == "__main__":
    main()

