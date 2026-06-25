#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
IP Range Downloader - دریافت رنج‌های IP کشورها
نسخه پایتون با نمایش لاگ زنده
"""

import os
import sys
import json
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional
import re
import threading

# ============================================
# تنظیمات
# ============================================

OUTPUT_DIR = "ip_ranges"
MAX_THREADS = 20
TIMEOUT = 10

# رنگ‌ها
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    CYAN = '\033[0;36m'
    MAGENTA = '\033[0;35m'
    WHITE = '\033[1;37m'
    NC = '\033[0m'
    BOLD = '\033[1m'

# ============================================
# لیست کشورها
# ============================================

COUNTRIES = [
    "AF", "AL", "DZ", "AS", "AD", "AO", "AI", "AQ", "AG", "AR", "AM", "AW", 
    "AU", "AT", "AZ", "BS", "BH", "BD", "BB", "BY", "BE", "BZ", "BJ", "BM", 
    "BT", "BO", "BA", "BW", "BR", "BN", "BG", "BF", "BI", "KH", "CM", "CA", 
    "CV", "KY", "CF", "TD", "CL", "CN", "CO", "KM", "CG", "CD", "CK", "CR", 
    "CI", "HR", "CU", "CY", "CZ", "DK", "DJ", "DM", "DO", "EC", "EG", "SV", 
    "GQ", "ER", "EE", "ET", "FJ", "FI", "FR", "GA", "GM", "GE", "DE", "GH", 
    "GI", "GR", "GL", "GD", "GP", "GU", "GT", "GN", "GW", "GY", "HT", "HN", 
    "HK", "HU", "IS", "IN", "ID", "IR", "IQ", "IE", "IL", "IT", "JM", "JP", 
    "JO", "KZ", "KE", "KI", "KP", "KR", "KW", "KG", "LA", "LV", "LB", "LS", 
    "LR", "LY", "LI", "LT", "LU", "MO", "MG", "MW", "MY", "MV", "ML", "MT", 
    "MH", "MQ", "MR", "MU", "YT", "MX", "FM", "MD", "MC", "MN", "ME", "MS", 
    "MA", "MZ", "MM", "NA", "NR", "NP", "NL", "NC", "NZ", "NI", "NE", "NG", 
    "NU", "NF", "MP", "NO", "OM", "PK", "PW", "PS", "PA", "PG", "PY", "PE", 
    "PH", "PN", "PL", "PT", "PR", "QA", "RE", "RO", "RU", "RW", "SH", "KN", 
    "LC", "PM", "VC", "WS", "SM", "ST", "SA", "SN", "RS", "SC", "SL", "SG", 
    "SK", "SI", "SB", "SO", "ZA", "GS", "ES", "LK", "SD", "SR", "SJ", "SZ", 
    "SE", "CH", "SY", "TW", "TJ", "TZ", "TH", "TL", "TG", "TK", "TO", "TT", 
    "TN", "TR", "TM", "TC", "TV", "UG", "UA", "AE", "GB", "US", "UM", "UY", 
    "UZ", "VU", "VE", "VN", "VG", "VI", "WF", "EH", "YE", "ZM", "ZW"
]

# ============================================
# منابع معتبر
# ============================================

SOURCES = [
    {
        'name': 'ipdeny',
        'url': 'http://www.ipdeny.com/ipblocks/data/countries/{country}.zone',
        'enabled': True
    },
    {
        'name': 'ip2location',
        'url': 'https://raw.githubusercontent.com/ip2location/ip2location-iab/master/IP2LOCATION-COUNTRY/{country}.ip2location',
        'enabled': True
    },
    {
        'name': 'country-ip-blocks',
        'url': 'https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/{country}.cidr',
        'enabled': True
    },
    {
        'name': 'ipverse',
        'url': 'https://raw.githubusercontent.com/ipverse/asn-ip/master/countries/{country}/ipv4.txt',
        'enabled': True
    },
    {
        'name': 'firehol',
        'url': 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/ipip_country/ipip_country_{country}.netset',
        'enabled': True
    }
]

class IPRangeDownloader:
    def __init__(self):
        self.output_dir = OUTPUT_DIR
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        os.makedirs(self.output_dir, exist_ok=True)
        
        
        self.total = 0
        self.success = 0
        self.failed = 0
        self.current_country = ""
        self.current_status = ""
        self.start_time = 0
        self.lock = threading.Lock()
        self.completed = 0
        self.last_line_len = 0
        
    def print_header(self):
        print(f"{Colors.CYAN}╔══════════════════════════════════════════════════════════╗{Colors.NC}")
        print(f"{Colors.CYAN}║               IP range scanner | BlackCode               ║{Colors.NC}")
        print(f"{Colors.CYAN}║        Github: https://github.com/nullBlackCode          ║{Colors.NC}")
        print(f"{Colors.CYAN}╚══════════════════════════════════════════════════════════╝{Colors.NC}")
        print("")
    
    def clear_line(self):
        sys.stdout.write('\r' + ' ' * self.last_line_len + '\r')
        sys.stdout.flush()
        self.last_line_len = 0
    
    def print_live_status(self):
        elapsed = int(time.time() - self.start_time) if self.start_time > 0 else 0
        
        progress = (self.completed / self.total) * 100 if self.total > 0 else 0
        bar_width = 20
        filled = int(bar_width * progress / 100)
        bar = '█' * filled + '░' * (bar_width - filled)
        status_line = (
            f"\r{Colors.CYAN}[{bar}] {Colors.NC}"
            f"{Colors.YELLOW}{progress:5.1f}%{Colors.NC} | "
            f"{Colors.WHITE}{self.completed}/{self.total}{Colors.NC} | "
            f"{Colors.GREEN}✅ {self.success}{Colors.NC} | "
            f"{Colors.RED}❌ {self.failed}{Colors.NC} | "
            f"{Colors.BLUE}⏱️  {elapsed}s{Colors.NC} | "
            f"{Colors.MAGENTA}🌍 {self.current_country}{Colors.NC}"
        )
        if self.current_status:
            status_line += f" | {Colors.YELLOW}{self.current_status}{Colors.NC}"
        sys.stdout.write('\r' + ' ' * self.last_line_len + '\r')
        sys.stdout.write(status_line)
        sys.stdout.flush()
        self.last_line_len = len(status_line.replace('\033[0m', '').replace('\033[1m', '').replace('\033[0;31m', '').replace('\033[0;32m', '').replace('\033[1;33m', '').replace('\033[0;34m', '').replace('\033[0;36m', '').replace('\033[0;35m', ''))
    
    def print_log(self, message, color=Colors.WHITE, new_line=False):
        self.clear_line()
        if new_line:
            print(f"{color}{message}{Colors.NC}")
        else:
            print(f"{color}{message}{Colors.NC}", end='')
        self.print_live_status()
    
    def download_from_source(self, country: str, source: dict) -> List[str]:
        try:
            url = source['url'].format(country=country.lower())
            response = self.session.get(url, timeout=TIMEOUT)
            
            if response.status_code != 200:
                return []
            
            lines = response.text.split('\n')
            ip_ranges = []
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                if re.match(r'^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$', line):
                    ip_ranges.append(line)
            
            return ip_ranges
            
        except Exception as e:
            return []
    
    def download_country(self, country: str) -> bool:
        output_file = os.path.join(self.output_dir, f"{country}_ip_ranges.txt")
        
        with self.lock:
            self.current_country = country
            self.current_status = "🔍 Searching..."
            self.print_live_status()
        
        all_ranges = []
        source_count = 0
        
        for source in SOURCES:
            if not source['enabled']:
                continue
            
            source_count += 1
            
            with self.lock:
                self.current_status = f"📥 {source['name']}..."
                self.print_live_status()
            
            ranges = self.download_from_source(country, source)
            
            if ranges:
                with self.lock:
                    self.current_status = f"✅ {len(ranges)} ranges from {source['name']}"
                    self.print_live_status()
                all_ranges.extend(ranges)
                break
            else:
                with self.lock:
                    self.current_status = f"❌ {source['name']} failed"
                    self.print_live_status()
                time.sleep(0.1)
        
        if not all_ranges:
            with self.lock:
                self.current_status = "⚠️  Using fallback"
                self.print_live_status()
            
            with open(output_file, 'w') as f:
                f.write("0.0.0.0/0\n")
            
            with self.lock:
                self.failed += 1
                self.completed += 1
                self.current_status = "❌ Failed"
                self.print_live_status()
            
            return False
        
        all_ranges = sorted(set(all_ranges))
        
        with open(output_file, 'w') as f:
            for ip_range in all_ranges:
                f.write(f"{ip_range}\n")
        
        with self.lock:
            self.success += 1
            self.completed += 1
            self.current_status = f"✅ {len(all_ranges)} ranges"
            self.print_live_status()
        
        return True
    
    def download_all_countries(self):
        self.print_header()
        
        self.total = len(COUNTRIES)
        self.completed = 0
        self.success = 0
        self.failed = 0
        self.start_time = time.time()
        
        print(f"{Colors.CYAN}📊 Total countries: {self.total}{Colors.NC}")
        print(f"{Colors.CYAN}🚀 Threads: {MAX_THREADS}{Colors.NC}")
        print(f"{Colors.CYAN}⏱️  Timeout: {TIMEOUT}s{Colors.NC}")
        print("")
        print(f"{Colors.YELLOW}📡 Live Log - Watching...{Colors.NC}")
        print("")
        
        self.print_live_status()
        
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = {
                executor.submit(self.download_country, country): country 
                for country in COUNTRIES
            }
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    with self.lock:
                        self.failed += 1
                        self.completed += 1
                        self.current_status = f"❌ Error: {str(e)[:30]}"
                        self.print_live_status()
        
        self.clear_line()
        print("")
    
        self.print_statistics()
    
    def download_specific_country(self, country: str):
        self.print_header()
        
        country = country.upper()
        
        if country not in COUNTRIES:
            print(f"{Colors.RED}❌ Country code '{country}' not found!{Colors.NC}")
            print(f"{Colors.YELLOW}💡 Use -l to see all country codes{Colors.NC}")
            return
        
        self.total = 1
        self.completed = 0
        self.success = 0
        self.failed = 0
        self.start_time = time.time()
        
        print(f"{Colors.CYAN}📊 Downloading: {country}{Colors.NC}")
        print("")
        
        self.print_live_status()
        
        self.download_country(country)
        
        self.clear_line()
        print("")
        self.print_statistics()
    
    def print_statistics(self):
        elapsed = int(time.time() - self.start_time) if self.start_time > 0 else 0
        
        print(f"\n{Colors.GREEN}╔══════════════════════════════════════════════════════════╗{Colors.NC}")
        print(f"{Colors.GREEN}║                    FINAL STATISTICS                      ║{Colors.NC}")
        print(f"{Colors.GREEN}╚══════════════════════════════════════════════════════════╝{Colors.NC}")
        print("")
        print(f"{Colors.YELLOW}📊 Total Countries: {self.total}{Colors.NC}")
        print(f"{Colors.GREEN}✅ Successful: {self.success}{Colors.NC}")
        print(f"{Colors.RED}❌ Failed: {self.failed}{Colors.NC}")
        print(f"{Colors.CYAN}⏱️  Time: {elapsed} seconds{Colors.NC}")
        
        if self.total > 0:
            success_rate = (self.success / self.total) * 100
            print(f"{Colors.MAGENTA}📈 Success Rate: {success_rate:.1f}%{Colors.NC}")
        
        print(f"{Colors.CYAN}📁 Output Directory: {self.output_dir}/{Colors.NC}")
        print("")
        
        self.create_combined_file()
    
    def create_combined_file(self):
        print(f"{Colors.BLUE}[+] Creating combined file...{Colors.NC}")
        
        combined_file = os.path.join(self.output_dir, "all_countries_ip_ranges.txt")
        all_ranges = set()
        
        for filename in os.listdir(self.output_dir):
            if filename.endswith("_ip_ranges.txt") and filename != "all_countries_ip_ranges.txt":
                filepath = os.path.join(self.output_dir, filename)
                try:
                    with open(filepath, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if line and line != "0.0.0.0/0":
                                all_ranges.add(line)
                except:
                    pass
        
        with open(combined_file, 'w') as f:
            for ip_range in sorted(all_ranges):
                f.write(f"{ip_range}\n")
        
        print(f"{Colors.GREEN}✅ Combined file created: {combined_file}{Colors.NC}")
        print(f"{Colors.CYAN}   Total unique IP ranges: {len(all_ranges)}{Colors.NC}")
    
    def show_country_list(self):
        self.print_header()
        
        print(f"{Colors.YELLOW}📋 List of Country Codes (ISO 3166-1 alpha-2):{Colors.NC}")
        print("")
        
        categories = {
            '🌍 Middle East': ["IR", "IQ", "SY", "JO", "LB", "SA", "YE", "OM", "AE", "QA", "KW", "BH", "TR", "IL", "PS", "EG", "LY", "DZ", "MA", "TN"],
            '🌍 Europe': ["GB", "DE", "FR", "IT", "ES", "NL", "SE", "NO", "DK", "FI", "PL", "UA", "RO", "GR", "PT", "BE", "CH", "AT", "RU"],
            '🌍 Asia': ["CN", "IN", "JP", "KR", "ID", "PK", "BD", "VN", "TH", "MY", "SG", "PH", "TW", "HK"],
            '🌍 Americas': ["US", "CA", "MX", "BR", "AR", "CO", "CL", "PE"],
            '🌍 Africa': ["EG", "ZA", "NG", "KE", "MA", "DZ"],
            '🌍 Oceania': ["AU", "NZ"]
        }
        
        for category, countries in categories.items():
            print(f"{Colors.CYAN}{category}:{Colors.NC}")
            for i in range(0, len(countries), 10):
                chunk = countries[i:i+10]
                print(f"  {' '.join(chunk)}")
            print("")
        print(f"{Colors.YELLOW}💡 Use -c CODE to download specific country{Colors.NC}")
        print(f"{Colors.YELLOW}💡 Use -a to download all countries{Colors.NC}")

def main():
    if len(sys.argv) < 2:
        print(f"{Colors.RED}❌ Error: No option provided{Colors.NC}")
        print(f"{Colors.YELLOW}💡 Use -h for help{Colors.NC}")
        sys.exit(1)
    
    downloader = IPRangeDownloader()
    
    option = sys.argv[1]
    
    if option in ['-a', '--all']:
        downloader.download_all_countries()
    
    elif option in ['-c', '--country']:
        if len(sys.argv) < 3:
            print(f"{Colors.RED}❌ Error: Please specify a country code{Colors.NC}")
            print(f"{Colors.YELLOW}Example: python3 ip_downloader.py -c IR{Colors.NC}")
            sys.exit(1)
        downloader.download_specific_country(sys.argv[2])
    
    elif option in ['-l', '--list']:
        downloader.show_country_list()
    
    elif option in ['-h', '--help']:
        print("")
        print(f"{Colors.YELLOW}Options:{Colors.NC}")
        print("  -a, --all          Download IP ranges for ALL countries")
        print("  -c, --country CODE Download IP range for specific country")
        print("  -l, --list         Show list of all country codes")
        print("  -h, --help         Show this help")
        print("")
    
    else:
        print(f"{Colors.RED}❌ Unknown option: {option}{Colors.NC}")
        print(f"{Colors.YELLOW}💡 Use -h for help{Colors.NC}")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}⚠️  Interrupted by user{Colors.NC}")
        sys.exit(0)
