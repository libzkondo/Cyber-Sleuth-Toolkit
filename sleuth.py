#!/usr/bin/env python3
import argparse
import sys
import socket
import concurrent.futures
import os
import urllib.request
import urllib.error
from datetime import datetime

# --- Configuration ---
VERSION = "1.6.2-Smart"
TOOL_NAME = "Cyber Sleuth Toolkit"
MAX_THREADS = 50

# --- Colors ---
GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[96m"

# --- Global Storage ---
scan_results = []
subdomain_results = []
header_results = []
whois_data = "No WHOIS data requested."

SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "test", "dev", "admin", "forum", "blog", "vpn", "secure", "shop", "api"
]

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def banner():
    print(f"""{GREEN}{BOLD}
    ===========================================
      {TOOL_NAME} v{VERSION}
      created by Liberty Kondo
    ===========================================
    {RESET}""")

# --- Module: HTML Reporting ---
def generate_html_report(filename, target):
    print(f"\n[*] Generating HTML Report: {filename}...")
    sub_content = "".join([f"<li>{s}</li>" for s in subdomain_results]) if subdomain_results else "<li>No subdomains found.</li>"
    
    html_content = f"""
    <html>
    <head>
        <title>{TOOL_NAME} Report - {target}</title>
        <style>
            body {{ font-family: sans-serif; background: #f4f4f4; color: #333; }}
            .container {{ width: 90%; margin: 20px auto; background: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
            h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; }}
            h2 {{ color: #e67e22; margin-top: 30px; }}
            table {{ width: 100%; border-collapse: collapse; }}
            th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; }}
            th {{ background: #2c3e50; color: white; }}
            .missing {{ color: red; font-weight: bold; background: #ffe6e6; }}
            .present {{ color: green; font-weight: bold; background: #e6fffa; }}
            pre {{ background: #eee; padding: 10px; overflow-x: auto; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Cyber Sleuth Security Report</h1>
            <p><strong>Target:</strong> {target} | <strong>Date:</strong> {datetime.now()}</p>
            <h2>1. Port Scan Results</h2>
            <table><tr><th>Port</th><th>Status</th><th>Banner</th></tr>
            {"".join([f"<tr><td>{r['port']}</td><td>OPEN</td><td>{r['banner']}</td></tr>" for r in scan_results])}
            </table>
            <h2>2. HTTP Headers</h2>
            <table><tr><th>Header</th><th>Status</th><th>Value</th></tr>
            {"".join([f"<tr><td>{h['header']}</td><td class='{h['status_class']}'>{h['status']}</td><td>{h['value']}</td></tr>" for h in header_results])}
            </table>
            <h2>3. Subdomains</h2><ul>{sub_content}</ul>
            <h2>4. WHOIS</h2><pre>{whois_data[:2000]}</pre>
        </div>
    </body>
    </html>
    """
    try:
        with open(filename, "w") as f:
            f.write(html_content)
        print(f"{GREEN}[+] Report saved to {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error saving report: {e}{RESET}")

# --- Scanning Modules ---
def check_port(target_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        if sock.connect_ex((target_ip, port)) == 0:
            try:
                sock.send(b'HEAD / HTTP/1.0\r\nUser-Agent: Mozilla/5.0\r\n\r\n')
                return port, True, sock.recv(1024).decode().strip()
            except:
                return port, True, "Unknown"
        sock.close()
    except: pass
    return port, False, None

def scan_ports(target, ports):
    print(f"\n[*] Starting Port Scan on {target}...")
    try:
        target_ip = socket.gethostbyname(target)
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            future_to_port = {executor.submit(check_port, target_ip, port): port for port in ports}
            for future in concurrent.futures.as_completed(future_to_port):
                port, is_open, banner = future.result()
                if is_open:
                    print(f"{GREEN}[+] Port {port}: OPEN{RESET}")
                    scan_results.append({"port": port, "banner": banner})
    except: print(f"{RED}[!] Hostname resolution failed.{RESET}")

def analyze_headers(target):
    print(f"\n[*] Analyzing Headers for {target} (Smart Redirects)...")
    
    # We start with HTTP. urllib will automatically follow 301 redirects to HTTPS.
    url = f"http://{target}"
    
    try:
        # Create a "Browser-like" request
        req = urllib.request.Request(
            url, 
            method='HEAD', 
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        )
        
        # Open connection (follows redirects automatically)
        with urllib.request.urlopen(req, timeout=10) as response:
            headers = response.info()
            final_url = response.geturl()
            print(f"{CYAN}[*] Followed redirects to: {final_url}{RESET}")
            
            reqs = ["X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options"]
            
            for r in reqs:
                # Headers in urllib are case-insensitive, but we check carefully
                val = headers.get(r)
                if val:
                    print(f"{GREEN}[+] {r}: PRESENT{RESET}")
                    header_results.append({"header": r, "status": "PRESENT", "status_class": "present", "value": val[:50]})
                else:
                    print(f"{RED}[-] {r}: MISSING{RESET}")
                    header_results.append({"header": r, "status": "MISSING", "status_class": "missing", "value": "N/A"})

    except urllib.error.URLError as e:
        print(f"{RED}[!] Connection failed: {e.reason}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")

def enum_subdomains(domain):
    print(f"\n[*] Enumerating Subdomains for {domain}...")
    def check(sub):
        try:
            return sub, socket.gethostbyname(f"{sub}.{domain}")
        except: return None, None

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        for future in concurrent.futures.as_completed({executor.submit(check, sub): sub for sub in SUBDOMAINS}):
            sub, ip = future.result()
            if sub:
                print(f"{GREEN}[+] Found: {sub}.{domain} -> {ip}{RESET}")
                subdomain_results.append(f"{sub}.{domain} ({ip})")

def get_whois(domain):
    global whois_data
    print(f"\n[*] Fetching WHOIS for {domain}...")
    def query(server, d):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((server, 43)); s.send(f"{d}\r\n".encode())
            return b"".join(iter(lambda: s.recv(4096), b"")).decode('utf-8', errors='ignore')
        except: return ""
    
    data = query("whois.iana.org", domain)
    referral = next((l.split(":")[-1].strip() for l in data.splitlines() if "refer:" in l), None)
    whois_data = query(referral, domain) if referral else data
    print(f"{GREEN}[+] WHOIS Data Retrieved.{RESET}")

# --- Interactive Menu ---
def interactive_mode():
    clear_screen()
    banner()
    print("Welcome to Interactive Mode. Select an option:\n")
    print("1. Quick Scan (Ports Only)")
    print("2. Full Recon (Ports + Headers + Subdomains + WHOIS)")
    print("3. Exit")
    
    choice = input(f"\n{BOLD}Select an option [1-3]: {RESET}")
    
    if choice == '3':
        sys.exit()
    
    target = input(f"{BOLD}Enter Target Domain (e.g., github.com): {RESET}")
    report_file = input(f"{BOLD}Output HTML Filename (press Enter to skip): {RESET}")
    
    if choice == '1':
        scan_ports(target, [21,22,80,443,3306,8080])
    elif choice == '2':
        scan_ports(target, [21,22,80,443,3306,8080])
        analyze_headers(target)
        enum_subdomains(target)
        get_whois(target)
    
    if report_file:
        generate_html_report(report_file, target)

# --- Main ---
def main():
    if len(sys.argv) == 1:
        interactive_mode()
    else:
        # Argument Mode (for scripting/automation)
        banner()
        parser = argparse.ArgumentParser()
        parser.add_argument("-t", "--target", help="Target Domain", required=True)
        parser.add_argument("--full", action="store_true", help="Run full recon")
        parser.add_argument("--html", help="HTML Report filename")
        args = parser.parse_args()
        
        scan_ports(args.target, [21,22,80,443,8080])
        if args.full:
            analyze_headers(args.target)
            enum_subdomains(args.target)
            get_whois(args.target)
        if args.html:
            generate_html_report(args.html, args.target)

if __name__ == "__main__":
    main()

