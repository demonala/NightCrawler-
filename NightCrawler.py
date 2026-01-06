#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NIGHTCRAWLER
Author: [REDACTED]
Date: 1998-xx-xx
Location: [REDACTED]
"""

import sys
import os
import time
import socket
import threading
import hashlib
import base64
import json
import random
import re
import urllib.request
import urllib.parse
import ipaddress
import subprocess
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import dns.resolver
import requests
from bs4 import BeautifulSoup
import whois
import ssl
import http.client

# ========== CONFIGURATION ==========
VERSION = "3.0"
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15'
]

# ========== UTILITIES ==========
class Logger:
    def __init__(self, log_file="nightcrawler.log"):
        self.log_file = log_file
        
    def log(self, message, level="INFO"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}"
        print(log_entry)
        
        with open(self.log_file, "a") as f:
            f.write(log_entry + "\n")

logger = Logger()

def get_headers():
    return {
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
    }

# ========== NETWORK SCANNER MODULE ==========
class NetworkScanner:
    def __init__(self, target):
        self.target = target
        self.open_ports = []
        
    def ping_sweep(self, network_range):
        """Ping sweep untuk network range"""
        alive_hosts = []
        
        try:
            network = ipaddress.ip_network(network_range, strict=False)
            total_hosts = network.num_addresses - 2
            
            print(f"[*] Scanning {network_range} ({total_hosts} hosts)")
            
            def check_host(ip):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((str(ip), 80))
                    sock.close()
                    if result == 0:
                        return str(ip)
                except:
                    pass
                return None
            
            with ThreadPoolExecutor(max_workers=100) as executor:
                futures = {executor.submit(check_host, ip): ip for ip in network.hosts()}
                
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        alive_hosts.append(result)
                        print(f"  [+] Host alive: {result}")
                        
        except Exception as e:
            logger.log(f"Ping sweep error: {e}", "ERROR")
            
        return alive_hosts
    
    def port_scan(self, ports="1-1024", timeout=1):
        """Port scanning dengan multi-threading"""
        try:
            if "-" in ports:
                start_port, end_port = map(int, ports.split("-"))
                port_list = range(start_port, end_port + 1)
            else:
                port_list = list(map(int, ports.split(",")))
        except:
            port_list = range(1, 1025)
            
        print(f"[*] Scanning {len(port_list)} ports on {self.target}")
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((self.target, port))
                sock.close()
                
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = "unknown"
                        
                    self.open_ports.append((port, service))
                    return port, service
            except:
                pass
            return None
            
        with ThreadPoolExecutor(max_workers=200) as executor:
            futures = {executor.submit(scan_port, port): port for port in port_list}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    print(f"  [+] {result[0]}/tcp open - {result[1]}")
                    
        return self.open_ports
    
    def get_banner(self, port):
        """Mendapatkan service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((self.target, port))
            
            if port in [80, 443, 8080, 8443]:
                sock.send(b"GET / HTTP/1.0\r\n\r\n")
            else:
                sock.send(b"\r\n")
                
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner[:200] if banner else "No banner"
        except:
            return "No banner"

# ========== WEB SCANNER MODULE ==========
class WebScanner:
    def __init__(self, url):
        self.url = url if url.startswith(('http://', 'https://')) else f'http://{url}'
        self.vulnerabilities = []
        
    def get_website_info(self):
        """Mendapatkan informasi website"""
        info = {}
        
        try:
            parsed = urllib.parse.urlparse(self.url)
            info['domain'] = parsed.netloc
            info['scheme'] = parsed.scheme
            info['path'] = parsed.path
            
            # Get IP
            try:
                ip = socket.gethostbyname(parsed.netloc)
                info['ip'] = ip
            except:
                info['ip'] = "Unknown"
                
            # Get headers
            response = requests.get(self.url, headers=get_headers(), timeout=10, verify=False)
            info['status_code'] = response.status_code
            info['headers'] = dict(response.headers)
            info['server'] = response.headers.get('Server', 'Unknown')
            info['technologies'] = self.detect_tech(response)
            
            # SSL Info
            if parsed.scheme == 'https':
                info['ssl'] = self.get_ssl_info(parsed.netloc)
                
            # WHOIS
            try:
                w = whois.whois(parsed.netloc)
                info['whois'] = {
                    'registrar': w.registrar,
                    'creation_date': str(w.creation_date),
                    'expiration_date': str(w.expiration_date)
                }
            except:
                info['whois'] = "Unable to fetch"
                
        except Exception as e:
            logger.log(f"Website info error: {e}", "ERROR")
            info['error'] = str(e)
            
        return info
    
    def detect_tech(self, response):
        """Detect web technologies"""
        tech = []
        
        # Check common headers
        headers = response.headers
        if 'X-Powered-By' in headers:
            tech.append(headers['X-Powered-By'])
        if 'Server' in headers:
            tech.append(f"Server: {headers['Server']}")
            
        # Check common patterns in HTML
        html = response.text.lower()
        
        tech_patterns = {
            'wordpress': ['wp-content', 'wp-includes', 'wordpress'],
            'joomla': ['joomla', 'content="joomla'],
            'drupal': ['drupal', 'sites/all'],
            'laravel': ['csrf-token', 'laravel'],
            'react': ['react', 'react-dom'],
            'vue': ['vue.js', '__vue__'],
            'jquery': ['jquery'],
            'bootstrap': ['bootstrap'],
            'nginx': ['nginx'],
            'apache': ['apache'],
            'php': ['.php', 'php/'],
            'asp.net': ['asp.net', '__viewstate']
        }
        
        for tech_name, patterns in tech_patterns.items():
            for pattern in patterns:
                if pattern in html:
                    tech.append(tech_name)
                    break
                    
        return list(set(tech))
    
    def get_ssl_info(self, hostname):
        """Get SSL certificate info"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    ssl_info = {
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'subject': dict(x[0] for x in cert['subject']),
                        'version': cert.get('version'),
                        'notBefore': cert.get('notBefore'),
                        'notAfter': cert.get('notAfter')
                    }
                    return ssl_info
        except:
            return "SSL info not available"
    
    def scan_vulnerabilities(self):
        """Basic vulnerability scanning"""
        vulns = []
        
        try:
            response = requests.get(self.url, headers=get_headers(), timeout=10, verify=False)
            
            # Check for common vulnerabilities
            # 1. SQL Injection patterns
            sql_errors = [
                "sql syntax",
                "mysql_fetch",
                "postgresql",
                "oracle",
                "sqlite",
                "syntax error",
                "unclosed quotation mark"
            ]
            
            # 2. XSS vulnerability
            test_payload = "<script>alert('test')</script>"
            test_url = f"{self.url}?test={urllib.parse.quote(test_payload)}"
            test_resp = requests.get(test_url, headers=get_headers(), timeout=5)
            
            if test_payload in test_resp.text:
                vulns.append("Possible XSS vulnerability")
                
            # 3. Directory traversal
            traversal_payload = "../../../etc/passwd"
            traversal_url = f"{self.url}?file={traversal_payload}"
            traversal_resp = requests.get(traversal_url, headers=get_headers(), timeout=5)
            
            if "root:" in traversal_resp.text:
                vulns.append("Possible directory traversal")
                
            # 4. Check for exposed admin panels
            admin_paths = [
                "/admin", "/administrator", "/wp-admin", 
                "/login", "/admin/login", "/backend",
                "/dashboard", "/controlpanel"
            ]
            
            for path in admin_paths:
                admin_url = f"{self.url}{path}"
                try:
                    admin_resp = requests.get(admin_url, headers=get_headers(), timeout=3)
                    if admin_resp.status_code == 200:
                        vulns.append(f"Exposed admin panel: {path}")
                except:
                    pass
                    
        except Exception as e:
            logger.log(f"Vulnerability scan error: {e}", "ERROR")
            
        return vulns
    
    def find_subdomains(self, wordlist="common_subdomains.txt"):
        """Find subdomains using wordlist"""
        subdomains = []
        domain = urllib.parse.urlparse(self.url).netloc
        
        # Default wordlist jika tidak ada file
        default_words = [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev',
            'staging', 'api', 'blog', 'shop', 'app', 'mobile'
        ]
        
        wordlist_to_use = default_words
        
        if os.path.exists(wordlist):
            try:
                with open(wordlist, 'r') as f:
                    wordlist_to_use = [line.strip() for line in f if line.strip()]
            except:
                wordlist_to_use = default_words
                
        print(f"[*] Scanning {len(wordlist_to_use)} subdomains for {domain}")
        
        def check_subdomain(sub):
            full_domain = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(full_domain)
                subdomains.append(full_domain)
                print(f"  [+] Found: {full_domain} -> {ip}")
                return full_domain
            except:
                return None
                
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(check_subdomain, word): word for word in wordlist_to_use}
            
            for future in as_completed(futures):
                future.result()
                
        return subdomains

# ========== OSINT MODULE ==========
class OSINTTool:
    def __init__(self):
        self.results = {}
        
    def dox_tracker(self, username):
        """Cari informasi berdasarkan username"""
        print(f"[*] Searching for username: {username}")
        
        sites = {
            'GitHub': f'https://github.com/{username}',
            'Twitter': f'https://twitter.com/{username}',
            'Instagram': f'https://instagram.com/{username}',
            'Facebook': f'https://facebook.com/{username}',
            'LinkedIn': f'https://linkedin.com/in/{username}',
            'YouTube': f'https://youtube.com/user/{username}',
            'Reddit': f'https://reddit.com/user/{username}'
        }
        
        found = []
        
        for site, url in sites.items():
            try:
                response = requests.get(url, headers=get_headers(), timeout=5)
                if response.status_code == 200:
                    found.append(site)
                    print(f"  [+] Found on {site}: {url}")
            except:
                pass
                
        return found
    
    def image_exif(self, image_path):
        """Extract EXIF data from image"""
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS
            
            image = Image.open(image_path)
            exif_data = {}
            
            if hasattr(image, '_getexif'):
                exif = image._getexif()
                if exif:
                    for tag, value in exif.items():
                        decoded = TAGS.get(tag, tag)
                        exif_data[decoded] = value
                        
            return exif_data
        except ImportError:
            return {"error": "PIL/Pillow not installed"}
        except Exception as e:
            return {"error": str(e)}
    
    def google_dork(self, query, num_results=10):
        """Google dorking (educational purposes only)"""
        print(f"[*] Google dorking: {query}")
        
        try:
            search_url = f"https://www.google.com/search?q={urllib.parse.quote(query)}&num={num_results}"
            response = requests.get(search_url, headers=get_headers(), timeout=10)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                results = []
                
                for g in soup.find_all('div', class_='g'):
                    link = g.find('a', href=True)
                    title = g.find('h3')
                    
                    if link and title:
                        results.append({
                            'title': title.text,
                            'url': link['href']
                        })
                        
                return results
        except Exception as e:
            logger.log(f"Google dork error: {e}", "ERROR")
            
        return []
    
    def ip_lookup(self, ip_address):
        """Lookup IP information"""
        try:
            # Using ip-api.com (free tier)
            response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=5)
            data = response.json()
            
            if data['status'] == 'success':
                return {
                    'country': data.get('country'),
                    'region': data.get('regionName'),
                    'city': data.get('city'),
                    'isp': data.get('isp'),
                    'org': data.get('org'),
                    'as': data.get('as'),
                    'lat': data.get('lat'),
                    'lon': data.get('lon')
                }
        except:
            pass
            
        return {"error": "Unable to lookup IP"}
    
    def phone_lookup(self, phone_number):
        """Basic phone number lookup"""
        print(f"[*] Looking up phone number: {phone_number}")
        # Note: Actual lookup would require paid APIs
        return {"note": "Premium service required for detailed lookup"}
    
    def email_lookup(self, email):
        """Check if email exists"""
        print(f"[*] Checking email: {email}")
        
        # Basic format validation
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            return {"valid": False, "error": "Invalid email format"}
            
        # Check common email patterns
        domain = email.split('@')[1]
        
        try:
            # Try MX record lookup
            answers = dns.resolver.resolve(domain, 'MX')
            mx_records = [str(r.exchange) for r in answers]
            return {
                "valid": True,
                "domain": domain,
                "mx_records": mx_records[:3]
            }
        except:
            return {"valid": False, "error": "No MX records found"}

# ========== UTILITIES MODULE ==========
class Utilities:
    @staticmethod
    def phishing_simulator(target_url, template="login"):
        """Phishing simulation (for educational purposes only)"""
        print("[!] PHISHING SIMULATION - FOR EDUCATIONAL PURPOSES ONLY")
        
        templates = {
            "login": """
            <!DOCTYPE html>
            <html>
            <head>
                <title>Login Required</title>
            </head>
            <body>
                <h2>Login Required</h2>
                <form method="POST">
                    <input type="text" name="username" placeholder="Username"><br>
                    <input type="password" name="password" placeholder="Password"><br>
                    <button type="submit">Login</button>
                </form>
            </body>
            </html>
            """,
            "facebook": """
            <!DOCTYPE html>
            <html>
            <head>
                <title>Facebook - Log In</title>
            </head>
            <body>
                <h2 style="color: blue;">Facebook</h2>
                <form method="POST">
                    <input type="text" name="email" placeholder="Email or Phone"><br>
                    <input type="password" name="pass" placeholder="Password"><br>
                    <button type="submit">Log In</button>
                </form>
            </body>
            </html>
            """
        }
        
        html = templates.get(template, templates["login"])
        filename = f"phish_sim_{int(time.time())}.html"
        
        with open(filename, "w") as f:
            f.write(html)
            
        print(f"[+] Simulation page saved as: {filename}")
        print("[!] This is for SECURITY TESTING ONLY")
        
        return filename
    
    @staticmethod
    def password_cracker(file_path, wordlist="rockyou.txt", hash_type=None):
        """Basic password cracking utility"""
        print(f"[*] Attempting to crack: {file_path}")
        
        if hash_type:
            # Hash cracking
            print(f"[*] Hash type: {hash_type}")
            
            if not os.path.exists(wordlist):
                print("[!] Wordlist not found")
                return None
                
            with open(wordlist, 'r', encoding='latin-1') as f:
                for line in f:
                    password = line.strip()
                    # Simple MD5 example
                    if hash_type.lower() == "md5":
                        hashed = hashlib.md5(password.encode()).hexdigest()
                        if hashed == file_path:  # file_path is the hash in this case
                            return password
        else:
            # Assume ZIP file
            import zipfile
            
            if not os.path.exists(wordlist):
                print("[!] Wordlist not found")
                return None
                
            with open(wordlist, 'r', encoding='latin-1') as f:
                for line in f:
                    password = line.strip()
                    try:
                        with zipfile.ZipFile(file_path) as zf:
                            zf.extractall(pwd=password.encode())
                            print(f"[+] Password found: {password}")
                            return password
                    except:
                        pass
                        
        print("[-] Password not found")
        return None
    
    @staticmethod
    def password_encrypt(password, algorithm="sha256"):
        """Encrypt password"""
        algorithms = {
            "md5": hashlib.md5,
            "sha1": hashlib.sha1,
            "sha256": hashlib.sha256,
            "sha512": hashlib.sha512
        }
        
        if algorithm in algorithms:
            hasher = algorithms[algorithm]()
            hasher.update(password.encode())
            return hasher.hexdigest()
        else:
            return "Unknown algorithm"
    
    @staticmethod
    def generate_ips(count=10, network="192.168.1.0/24"):
        """Generate random IP addresses"""
        ips = []
        
        try:
            net = ipaddress.ip_network(network, strict=False)
            for _ in range(count):
                ip = str(net[random.randint(1, net.num_addresses - 2)])
                ips.append(ip)
        except:
            # Fallback to random IPs
            for _ in range(count):
                ips.append(f"192.168.{random.randint(1,255)}.{random.randint(1,255)}")
                
        return ips
    
    @staticmethod
    def get_darkweb_links():
        """Educational dark web information (NOT ACTUAL LINKS)"""
        info = """
        === DARK WEB EDUCATIONAL INFORMATION ===
        
        The dark web is part of the internet that isn't indexed by search engines
        and requires special software (like Tor) to access.
        
        Common dark web domains end with .onion
        
        WARNING:
        - Many sites on the dark web are illegal
        - Law enforcement monitors dark web activities
        - Malware is common on dark web sites
        - Never download files or click unknown links
        
        For security research, use:
        - TOR Browser (https://www.torproject.org/)
        - Virtual Machines for isolation
        - VPN for additional privacy
        
        This information is for EDUCATIONAL PURPOSES ONLY.
        """
        
        print(info)
        return info

# ========== MALWARE GENERATOR (EDUCATIONAL) ==========
class MalwareGenerator:
    @staticmethod
    def create_educational_payload():
        """Create educational payload (non-malicious)"""
        print("[!] CREATING EDUCATIONAL PAYLOAD - NON MALICIOUS")
        
        payload = """
        #!/usr/bin/env python3
        # EDUCATIONAL PAYLOAD - DO NOT USE FOR MALICIOUS PURPOSES
        
        import os
        import sys
        import platform
        
        print("=== SYSTEM INFORMATION (EDUCATIONAL) ===")
        print(f"OS: {platform.system()} {platform.release()}")
        print(f"Hostname: {platform.node()}")
        print(f"Python: {platform.python_version()}")
        
        # List files in current directory (example)
        print("\\nFiles in current directory:")
        for file in os.listdir('.'):
            if os.path.isfile(file):
                print(f"  - {file}")
                
        print("\\n=== END OF EDUCATIONAL PAYLOAD ===")
        """
        
        filename = f"educational_payload_{int(time.time())}.py"
        
        with open(filename, "w") as f:
            f.write(payload)
            
        print(f"[+] Educational payload saved as: {filename}")
        print("[!] This file does NOT contain malicious code")
        
        return filename

# ========== MAIN MENU ==========
def banner():
    print(f"""
    ╔═══════════════════════════════════════════════════════╗
    ║                NIGHTCRAWLER v{VERSION}                    ║
    ║         Complete Reconnaissance Suite                 ║
    ║       For Authorized Security Testing Only           ║
    ╚═══════════════════════════════════════════════════════╝
    """)

def main_menu():
    print("\n" + "═"*60)
    print("1. NETWORK SCANNER")
    print("   • Port Scanner • Ping Sweep • Network Discovery")
    print("2. WEB SCANNER")
    print("   • Vulnerability Scanner • Website Info • Subdomain Finder")
    print("3. OSINT TOOLS")
    print("   • Dox Tracker • EXIF Extractor • Google Dorks • IP Lookup")
    print("4. UTILITIES")
    print("   • Phishing Simulator • Password Tools • IP Generator")
    print("5. EDUCATIONAL PAYLOAD GENERATOR")
    print("6. Exit")
    print("═"*60)
    
    try:
        choice = input("\nSelect option: ").strip()
        return choice
    except KeyboardInterrupt:
        return '6'

def network_scanner_menu():
    print("\n[ NETWORK SCANNER ]")
    print("1. Port Scanner")
    print("2. Ping Sweep")
    print("3. Back")
    
    choice = input("\nSelect: ").strip()
    
    if choice == '1':
        target = input("Target IP/hostname: ").strip()
        ports = input("Ports (1-1000 or specific like 80,443,8080): ").strip() or "1-1000"
        
        scanner = NetworkScanner(target)
        scanner.port_scan(ports)
        
        if scanner.open_ports:
            print("\n[*] Banner grabbing...")
            for port, service in scanner.open_ports[:5]:  # Limit to 5
                banner = scanner.get_banner(port)
                print(f"  Port {port}: {banner}")
                
    elif choice == '2':
        network = input("Network range (e.g., 192.168.1.0/24): ").strip()
        scanner = NetworkScanner("")
        scanner.ping_sweep(network)

def web_scanner_menu():
    print("\n[ WEB SCANNER ]")
    url = input("Website URL: ").strip()
    
    if not url:
        print("[!] URL required")
        return
        
    scanner = WebScanner(url)
    
    print("\n1. Get Website Info")
    print("2. Scan Vulnerabilities")
    print("3. Find Subdomains")
    print("4. All of the above")
    
    choice = input("\nSelect: ").strip()
    
    if choice in ['1', '4']:
        print("\n[*] Getting website information...")
        info = scanner.get_website_info()
        
        print("\n=== WEBSITE INFORMATION ===")
        for key, value in info.items():
            if key != 'headers':
                print(f"{key}: {value}")
                
    if choice in ['2', '4']:
        print("\n[*] Scanning for vulnerabilities...")
        vulns = scanner.scan_vulnerabilities()
        
        if vulns:
            print("\n=== POTENTIAL VULNERABILITIES ===")
            for vuln in vulns:
                print(f"• {vuln}")
        else:
            print("[*] No obvious vulnerabilities found")
            
    if choice in ['3', '4']:
        print("\n[*] Finding subdomains...")
        scanner.find_subdomains()

def osint_menu():
    print("\n[ OSINT TOOLS ]")
    print("1. Username Search")
    print("2. Image EXIF Extractor")
    print("3. Google Dorking")
    print("4. IP Lookup")
    print("5. Email Check")
    print("6. Phone Lookup")
    
    choice = input("\nSelect: ").strip()
    osint = OSINTTool()
    
    if choice == '1':
        username = input("Username: ").strip()
        osint.dox_tracker(username)
        
    elif choice == '2':
        image_path = input("Image path: ").strip()
        if os.path.exists(image_path):
            exif = osint.image_exif(image_path)
            print("\n=== EXIF DATA ===")
            for key, value in exif.items():
                print(f"{key}: {value}")
        else:
            print("[!] File not found")
            
    elif choice == '3':
        query = input("Google dork query: ").strip()
        results = osint.google_dork(query)
        
        if results:
            print(f"\nFound {len(results)} results:")
            for i, result in enumerate(results[:5], 1):
                print(f"{i}. {result['title']}")
                print(f"   {result['url'][:80]}...")
        else:
            print("[*] No results found")
            
    elif choice == '4':
        ip = input("IP address: ").strip()
        info = osint.ip_lookup(ip)
        
        print("\n=== IP INFORMATION ===")
        for key, value in info.items():
            print(f"{key}: {value}")
            
    elif choice == '5':
        email = input("Email address: ").strip()
        info = osint.email_lookup(email)
        
        print("\n=== EMAIL INFORMATION ===")
        for key, value in info.items():
            print(f"{key}: {value}")
            
    elif choice == '6':
        phone = input("Phone number: ").strip()
        info = osint.phone_lookup(phone)
        print(f"Result: {info}")

def utilities_menu():
    print("\n[ UTILITIES ]")
    print("1. Phishing Simulator (Educational)")
    print("2. Password Cracker")
    print("3. Password Encrypt")
    print("4. Dark Web Info")
    print("5. IP Generator")
    
    choice = input("\nSelect: ").strip()
    utils = Utilities()
    
    if choice == '1':
        url = input("Target URL (for simulation): ").strip()
        template = input("Template (login/facebook): ").strip() or "login"
        utils.phishing_simulator(url, template)
        
    elif choice == '2':
        file_path = input("File path or hash: ").strip()
        hash_type = input("Hash type (md5,sha256) or leave blank for ZIP: ").strip() or None
        wordlist = input("Wordlist path (optional): ").strip() or "rockyou.txt"
        utils.password_cracker(file_path, wordlist, hash_type)
        
    elif choice == '3':
        password = input("Password to encrypt: ").strip()
        algo = input("Algorithm (md5,sha1,sha256,sha512): ").strip() or "sha256"
        encrypted = utils.password_encrypt(password, algo)
        print(f"Hash ({algo}): {encrypted}")
        
    elif choice == '4':
        utils.get_darkweb_links()
        
    elif choice == '5':
        count = input("Number of IPs to generate: ").strip() or "10"
        network = input("Network (e.g., 10.0.0.0/24): ").strip() or "192.168.1.0/24"
        
        ips = utils.generate_ips(int(count), network)
        print(f"\nGenerated {len(ips)} IPs:")
        for ip in ips:
            print(f"  {ip}")

def main():
    try:
        os.system('clear' if os.name == 'posix' else 'cls')
        banner()
        
        print(f"[*] Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("[*] Log file: nightcrawler.log")
        print("[!] FOR EDUCATIONAL PURPOSES ONLY\n")
        
        while True:
            choice = main_menu()
            
            if choice == '1':
                network_scanner_menu()
            elif choice == '2':
                web_scanner_menu()
            elif choice == '3':
                osint_menu()
            elif choice == '4':
                utilities_menu()
            elif choice == '5':
                print("\n[ EDUCATIONAL PAYLOAD GENERATOR ]")
                print("[!] This creates NON-MALICIOUS code for educational purposes")
                confirm = input("Continue? (y/n): ").strip().lower()
                if confirm == 'y':
                    MalwareGenerator.create_educational_payload()
            elif choice == '6':
                print("\n[*] Exiting NightCrawler...")
                logger.log("NightCrawler session ended", "INFO")
                break
            else:
                print("[!] Invalid option")
            
            input("\nPress Enter to continue...")
            os.system('clear' if os.name == 'posix' else 'cls')
            banner()
            
    except KeyboardInterrupt:
        print("\n\n[*] Interrupted by user")
        logger.log("Session interrupted", "INFO")
    except Exception as e:
        print(f"\n[!] Error: {e}")
        logger.log(f"Critical error: {e}", "ERROR")

if __name__ == "__main__":
    # Create necessary directories
    if not os.path.exists("logs"):
        os.makedirs("logs", exist_ok=True)
    
    # Check dependencies
    try:
        import requests
        import beautifulsoup4
    except ImportError:
        print("[!] Installing required packages...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", 
                                 "requests", "beautifulsoup4", "dnspython", "whois"])
            print("[+] Packages installed successfully")
        except:
            print("[!] Failed to install packages")
            print("[!] Please install manually: pip install requests beautifulsoup4 dnspython whois")
    
    main()
