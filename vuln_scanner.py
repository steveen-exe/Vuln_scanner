import requests
from bs4 import BeautifulSoup
import socket
from datetime import datetime
import argparse
import json
import os
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, init

# Init colorama
init(autoreset=True)

COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
    443: 'HTTPS', 3306: 'MySQL', 8080: 'HTTP-Alt'
}

visited_links = set()
report_data = {
    "target": "",
    "headers": [],
    "xss": [],
    "sqli": [],
    "ports": []
}

def write_report_text(report_file, text):
    with open(report_file, "a") as f:
        f.write(text + "\n")

def write_report_json(json_file):
    with open(json_file, "w") as f:
        json.dump(report_data, f, indent=4)

def check_security_headers(url, report_file):
    print(Fore.CYAN + "\n[+] Checking security headers...")
    write_report_text(report_file, "\n[+] Security Header Check:")
    try:
        response = requests.get(url)
        headers = response.headers
        required = {
            "Strict-Transport-Security", "Content-Security-Policy",
            "X-Content-Type-Options", "X-XSS-Protection", "X-Frame-Options"
        }
        for header in required:
            if header in headers:
                msg = f"    [✔] {header} is present"
                print(Fore.GREEN + msg)
            else:
                msg = f"    [!] {header} is missing"
                print(Fore.RED + msg)
            write_report_text(report_file, msg)
            report_data["headers"].append(msg)
    except Exception as e:
        err = f"    [!] Error fetching headers: {e}"
        print(Fore.RED + err)
        write_report_text(report_file, err)

def crawl_links(base_url):
    to_crawl = [base_url]
    while to_crawl:
        url = to_crawl.pop()
        if url in visited_links:
            continue
        visited_links.add(url)
        try:
            res = requests.get(url)
            soup = BeautifulSoup(res.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                new_url = urljoin(base_url, link['href'])
                if urlparse(new_url).netloc == urlparse(base_url).netloc:
                    to_crawl.append(new_url)
        except:
            continue
    return list(visited_links)

def check_xss(url, report_file):
    print(Fore.CYAN + "\n[+] Checking for XSS on internal forms...")
    write_report_text(report_file, "\n[+] XSS Check:")
    try:
        urls = crawl_links(url)
        for page in urls:
            res = requests.get(page)
            soup = BeautifulSoup(res.text, 'html.parser')
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action')
                method = form.get('method', 'get').lower()
                inputs = form.find_all('input')
                data = {i.get('name'): '<script>alert(1)</script>' for i in inputs if i.get('name')}
                target = urljoin(page, action) if action else page
                resp = requests.post(target, data=data) if method == 'post' else requests.get(target, params=data)
                if '<script>alert(1)</script>' in resp.text:
                    msg = f"    [!] Possible XSS in form at {target}"
                    print(Fore.YELLOW + msg)
                else:
                    msg = f"    [✔] No XSS at {target}"
                    print(Fore.GREEN + msg)
                write_report_text(report_file, msg)
                report_data["xss"].append(msg)
    except Exception as e:
        err = f"    [!] Error during XSS check: {e}"
        print(Fore.RED + err)
        write_report_text(report_file, err)

def check_sqli(url, report_file):
    print(Fore.CYAN + "\n[+] Checking for SQL Injection...")
    write_report_text(report_file, "\n[+] SQL Injection Check:")
    try:
        payload = "' OR '1'='1"
        test_url = f"{url}?id={payload}"
        res = requests.get(test_url)
        errors = ["sql syntax", "mysql", "ORA-", "sqlite", "unexpected token"]
        found = any(err.lower() in res.text.lower() for err in errors)
        msg = f"    [!] Possible SQLi at {test_url}" if found else "    [✔] No SQLi found"
        color = Fore.YELLOW if found else Fore.GREEN
        print(color + msg)
        write_report_text(report_file, msg)
        report_data["sqli"].append(msg)
    except Exception as e:
        err = f"    [!] Error during SQLi check: {e}"
        print(Fore.RED + err)
        write_report_text(report_file, err)

def scan_port(ip, port, report_file):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        if s.connect_ex((ip, port)) == 0:
            msg = f"    [✔] Port {port} ({COMMON_PORTS.get(port, 'Unknown')}) is OPEN"
            print(Fore.GREEN + msg)
            write_report_text(report_file, msg)
            report_data["ports"].append(msg)
        s.close()
    except:
        pass

def scan_ports(host, report_file):
    print(Fore.CYAN + "\n[+] Scanning common ports (multi-threaded)...")
    write_report_text(report_file, "\n[+] Port Scan:")
    try:
        ip = socket.gethostbyname(host)
        with ThreadPoolExecutor(max_workers=50) as executor:
            for port in COMMON_PORTS:
                executor.submit(scan_port, ip, port, report_file)
    except Exception as e:
        err = f"    [!] Port scan error: {e}"
        print(Fore.RED + err)
        write_report_text(report_file, err)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced CLI Vulnerability Scanner")
    parser.add_argument("--url", required=True, help="Target URL (e.g., http://example.com)")
    parser.add_argument("--report", help="Output text report file")
    parser.add_argument("--json", help="Output JSON report file")
    parser.add_argument("--xss", action="store_true", help="Run XSS scan")
    parser.add_argument("--sqli", action="store_true", help="Run SQLi scan")
    parser.add_argument("--headers", action="store_true", help="Check security headers")
    parser.add_argument("--ports", action="store_true", help="Scan common ports")
    args = parser.parse_args()

    url = args.url
    if not url.startswith("http"):
        url = "http://" + url
    host = url.split("//")[-1].split("/")[0]
    now = datetime.now().strftime("%Y-%m-%d_%H-%M")
    report_file = args.report or f"scan_report_{now}.txt"
    json_file = args.json or f"scan_report_{now}.json"
    report_data["target"] = url

    print(Fore.MAGENTA + "\n[***] Starting scan on " + url + " [***]")
    write_report_text(report_file, f"[*] Scan started on: {url}")

    if args.headers:
        check_security_headers(url, report_file)
    if args.xss:
        check_xss(url, report_file)
    if args.sqli:
        check_sqli(url, report_file)
    if args.ports:
        scan_ports(host, report_file)

    write_report_text(report_file, "[*] Scan complete.")
    write_report_json(json_file)
    print(Fore.GREEN + f"\n[+] Report saved to: {report_file}, {json_file}")
