#!/usr/bin/env python3
import argparse
import sys
import socket
import concurrent.futures
from datetime import datetime

# --- Configuration ---
VERSION = "1.4.0"
TOOL_NAME = "Cyber Sleuth Toolkit"
MAX_THREADS = 50

# Common subdomains to hunt for
SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "test", "dev", "admin", "forum", "blog", "vpn", "secure", "shop", "api",
    "portal", "remote", "dashboard", "crm", "payment", "support", "mobile"
]

def banner():
    print(f"""
    ===========================================
      {TOOL_NAME} v{VERSION}
      created by Liberty Kondo
    ===========================================
    """)

# --- Helper: File Saving ---
def save_to_file(filename, data):
    try:
        with open(filename, "a") as f:
            f.write(data + "\n")
    except Exception as e:
        print(f"[!] Error writing to file: {e}")

# --- Module: Port Scanner ---
def check_port(target_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            try:
                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                banner = sock.recv(1024).decode().strip()
                return port, True, banner
            except:
                return port, True, None
        sock.close()
    except:
        pass
    return port, False, None

def scan_ports(target, ports, output_file=None):
    print(f"\n[*] Starting Port Scan on {target}...")
    try:
        target_ip = socket.gethostbyname(target)
        print(f"[*] IP Address: {target_ip}")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            future_to_port = {executor.submit(check_port, target_ip, port): port for port in ports}
            for future in concurrent.futures.as_completed(future_to_port):
                port, is_open, banner_data = future.result()
                if is_open:
                    msg = f"[+] Port {port}: OPEN"
                    if banner_data: msg += f" -> {banner_data[:50]}"
                    print(msg)
                    if output_file: save_to_file(output_file, msg)
    except socket.gaierror:
        print("[!] Could not resolve hostname.")

# --- Module: Subdomain Enumeration ---
def check_subdomain(domain, sub):
    sub_domain = f"{sub}.{domain}"
    try:
        ip = socket.gethostbyname(sub_domain)
        return f"[+] Found: {sub_domain} -> {ip}"
    except:
        return None

def enum_subdomains(domain, output_file=None):
    print(f"\n[*] Starting Subdomain Enumeration on {domain}...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        future_to_sub = {executor.submit(check_subdomain, domain, sub): sub for sub in SUBDOMAINS}
        for future in concurrent.futures.as_completed(future_to_sub):
            result = future.result()
            if result:
                print(result)
                if output_file: save_to_file(output_file, result)

# --- Module: WHOIS Lookup ---
def perform_whois_query(server, domain):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((server, 43))
        s.send(f"{domain}\r\n".encode())
        response = ""
        while True:
            data = s.recv(4096)
            if not data: break
            response += data.decode('utf-8', errors='ignore')
        s.close()
        return response
    except Exception as e:
        return f"Error: {e}"

def get_whois(domain, output_file=None):
    print(f"\n[*] Performing WHOIS lookup for {domain}...")
    # 1. Query IANA to find the right registrar
    iana_response = perform_whois_query("whois.iana.org", domain)
    
    referral_server = None
    for line in iana_response.splitlines():
        if "refer:" in line:
            referral_server = line.split(":")[-1].strip()
            break
            
    if referral_server:
        print(f"[*] Redirecting to registrar: {referral_server}")
        final_response = perform_whois_query(referral_server, domain)
        print(final_response[:500] + "\n...[truncated]...") # Print first 500 chars to avoid screen flood
        if output_file: save_to_file(output_file, final_response)
    else:
        print(iana_response)
        if output_file: save_to_file(output_file, iana_response)

# --- Main ---
def main():
    banner()
    parser = argparse.ArgumentParser(description="Cyber Sleuth Toolkit - Reconnaissance Tool")
    parser.add_argument("-t", "--target", help="Target Domain or IP", required=True)
    parser.add_argument("-p", "--ports", help="Ports to scan (e.g. 20-100)", default="20-100")
    parser.add_argument("-o", "--output", help="Save results to file")
    
    # Mode flags
    parser.add_argument("--scan", action="store_true", help="Perform Port Scan")
    parser.add_argument("--subdomain", action="store_true", help="Perform Subdomain Enumeration")
    parser.add_argument("--whois", action="store_true", help="Perform WHOIS Lookup")
    
    args = parser.parse_args()
    
    # If no specific mode is selected, default to Port Scan
    if not (args.scan or args.subdomain or args.whois):
        args.scan = True

    if args.output:
        save_to_file(args.output, f"--- Report for {args.target} [{datetime.now()}] ---")

    if args.whois:
        get_whois(args.target, args.output)
        
    if args.subdomain:
        enum_subdomains(args.target, args.output)

    if args.scan:
        # Parse ports
        port_list = []
        if '-' in args.ports:
            start, end = map(int, args.ports.split('-'))
            port_list = range(start, end + 1)
        else:
            port_list = [int(p) for p in args.ports.split(',')]
        scan_ports(args.target, port_list, args.output)

if __name__ == "__main__":
    main()

