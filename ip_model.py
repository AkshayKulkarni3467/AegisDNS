import requests
import re
from ipaddress import ip_address, ip_network, IPv4Address, IPv6Address
from typing import List, Set, Optional, Dict, Union
from datetime import datetime, timedelta
from collections import defaultdict, deque
import os
import csv

class IPFilterSystem:
    def __init__(self):
        self.ip_blocklist: Set[str] = set()
        self.blocked_regions: Set[str] = set()
        self.blocked_asns: Set[int] = set()
        
        # GeoIP data structures
        self.ip_to_country: dict = {}
        self.ip_to_asn: dict = {}
        
        # Rate limiting structures
        self.ip_request_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.rate_limit_violations: Dict[str, int] = defaultdict(int)
        
        # Tor/VPN/Proxy detection
        self.tor_exit_nodes: Set[str] = set()
        self.vpn_ranges: Set[str] = set()
        self.proxy_ips: Set[str] = set()
        self.datacenter_ranges: Set[str] = set()
        
        # CSV feed storage
        self.feed_directory = 'ip_feeds'
        self.max_feed_files = 5
        self._ensure_feed_directory()
        
        # Auto-load latest feed on initialization
        self._load_latest_feed()
        
    def _ensure_feed_directory(self):
        """
        Create ip_feeds directory if it doesn't exist.
        """
        if not os.path.exists(self.feed_directory):
            os.makedirs(self.feed_directory)
            print(f"[+] Created directory: {self.feed_directory}")
    
    def _get_latest_feed_file(self) -> Optional[str]:
        """
        Get the path to the most recent feed CSV file.
        
        Returns:
            Path to latest CSV file or None if no feeds exist
        """
        try:
            feed_files = [
                f for f in os.listdir(self.feed_directory) 
                if f.startswith('malicious_') and f.endswith('.csv')
            ]
            
            if not feed_files:
                return None
            
            # Sort by filename (timestamp is in filename) - most recent last
            feed_files.sort()
            latest_file = feed_files[-1]
            
            return os.path.join(self.feed_directory, latest_file)
            
        except Exception as e:
            print(f"[-] Error finding latest feed: {e}")
            return None
    
    def _load_latest_feed(self) -> bool:
        """
        Load IPs from the most recent feed CSV file.
        Called automatically on initialization.
        
        Returns:
            True if feed loaded successfully, False otherwise
        """
        try:
            latest_feed = self._get_latest_feed_file()
            
            if not latest_feed:
                print(f"[!] No existing feed files found in {self.feed_directory}/")
                print(f"[!] Call update_blocklist() to fetch fresh threat intelligence")
                return False
            
            # Read CSV and load IPs
            with open(latest_feed, 'r', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    ip = row.get('ip', '').strip()
                    if ip:
                        try:
                            ip_address(ip)  # Validate
                            self.ip_blocklist.add(ip)
                        except ValueError:
                            continue
            
            print(f"[+] Loaded {len(self.ip_blocklist)} IPs from latest feed: {os.path.basename(latest_feed)}")
            return True
            
        except Exception as e:
            print(f"[-] Error loading latest feed: {e}")
            return False
    
    def _cleanup_old_feeds(self):
        """
        Keep only the most recent 5 feed CSV files.
        """
        try:
            # Get all malicious_*.csv files
            feed_files = [
                f for f in os.listdir(self.feed_directory) 
                if f.startswith('malicious_') and f.endswith('.csv')
            ]
            
            if len(feed_files) > self.max_feed_files:
                # Sort by filename (timestamp is in filename)
                feed_files.sort()
                
                # Delete oldest files
                files_to_delete = feed_files[:-self.max_feed_files]
                for file in files_to_delete:
                    file_path = os.path.join(self.feed_directory, file)
                    os.remove(file_path)
                    print(f"[+] Deleted old feed: {file}")
        
        except Exception as e:
            print(f"[-] Error cleaning up old feeds: {e}")
    
    def _save_feed_to_csv(self, feed_data: List[Dict[str, str]], feed_type: str = "malicious"):
        """
        Save feed data to CSV with timestamp.
        
        Args:
            feed_data: List of dicts with IP info
            feed_type: Type of feed (default: "malicious")
        """
        try:
            # Generate timestamp filename
            timestamp = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
            filename = f"{feed_type}_{timestamp}.csv"
            filepath = os.path.join(self.feed_directory, filename)
            
            # Write to CSV
            with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
                if feed_data:
                    fieldnames = feed_data[0].keys()
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(feed_data)
            
            print(f"[+] Feed saved: {filepath} ({len(feed_data)} entries)")
            
            # Cleanup old feeds
            self._cleanup_old_feeds()
            
            return filepath
            
        except Exception as e:
            print(f"[-] Error saving feed to CSV: {e}")
            return None
    
    def update_blocklist(self, flush_existing: bool = True) -> bool:
        """
        Pull real-time threat intelligence from IPsum feed.
        Supports both IPv4 and IPv6.
        Saves feed data to CSV and optionally flushes old data.
        
        Args:
            flush_existing: If True, clear existing blocklist before loading new data
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Flush existing IPs if requested
            if flush_existing:
                old_count = len(self.ip_blocklist)
                self.ip_blocklist.clear()
                print(f"[+] Flushed {old_count} existing IPs from blocklist")
            
            url = 'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt'
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            feed_data = []
            
            for line in response.text.splitlines():
                line = line.strip()
                if line and not line.startswith('#'):
                    parts = line.split()
                    if parts:
                        ip = parts[0]
                        threat_level = parts[1] if len(parts) > 1 else "unknown"
                        
                        # Validate both IPv4 and IPv6
                        try:
                            ip_obj = ip_address(ip)
                            self.ip_blocklist.add(ip)
                            
                            # Store for CSV
                            feed_data.append({
                                'ip': ip,
                                'ip_version': 'IPv4' if isinstance(ip_obj, IPv4Address) else 'IPv6',
                                'threat_level': threat_level,
                                'source': 'IPsum',
                                'timestamp': datetime.now().isoformat()
                            })
                        except ValueError:
                            continue
            
            # Save to CSV
            if feed_data:
                self._save_feed_to_csv(feed_data, "malicious")
            
            print(f"[+] Blocklist updated: {len(self.ip_blocklist)} IPs loaded (IPv4/IPv6)")
            return True
            
        except Exception as e:
            print(f"[-] Error updating blocklist: {e}")
            return False
    
    def update_tor_exit_nodes(self) -> bool:
        """
        Update list of Tor exit nodes from public sources.
        Supports IPv4 and IPv6 exit nodes.
        """
        try:
            # Dan.me.uk maintains a comprehensive list
            urls = [
                'https://check.torproject.org/torbulkexitlist',
                'https://www.dan.me.uk/torlist/'
            ]
            
            for url in urls:
                try:
                    response = requests.get(url, timeout=10)
                    response.raise_for_status()
                    
                    for line in response.text.splitlines():
                        line = line.strip()
                        if line and not line.startswith('#'):
                            try:
                                # Validate IP (IPv4 or IPv6)
                                ip_address(line)
                                self.tor_exit_nodes.add(line)
                            except ValueError:
                                continue
                    break  # If one succeeds, stop trying
                except Exception:
                    continue
            
            print(f"[+] Tor exit nodes updated: {len(self.tor_exit_nodes)} nodes")
            return True
            
        except Exception as e:
            print(f"[-] Error updating Tor exit nodes: {e}")
            return False
    
    def update_vpn_proxy_lists(self) -> bool:
        """
        Update VPN and proxy IP lists from public databases.
        Includes both IPv4 and IPv6 ranges.
        """
        try:
            # IPsum VPN feed
            vpn_sources = [
                'https://raw.githubusercontent.com/X4BNet/lists_vpn/main/ipv4.txt',
                'https://raw.githubusercontent.com/X4BNet/lists_vpn/main/ipv6.txt'
            ]
            
            for url in vpn_sources:
                try:
                    response = requests.get(url, timeout=10)
                    response.raise_for_status()
                    
                    for line in response.text.splitlines():
                        line = line.strip()
                        if line and not line.startswith('#'):
                            # Can be IP or CIDR range
                            try:
                                if '/' in line:
                                    ip_network(line, strict=False)
                                else:
                                    ip_address(line)
                                self.vpn_ranges.add(line)
                            except ValueError:
                                continue
                except Exception:
                    continue
            
            # Proxy list from public sources
            proxy_sources = [
                'https://raw.githubusercontent.com/stamparm/aux/master/malicious-ips.txt'
            ]
            
            for url in proxy_sources:
                try:
                    response = requests.get(url, timeout=10)
                    response.raise_for_status()
                    
                    for line in response.text.splitlines():
                        line = line.strip()
                        if line and not line.startswith('#'):
                            try:
                                ip_address(line)
                                self.proxy_ips.add(line)
                            except ValueError:
                                continue
                except Exception:
                    continue
            
            print(f"[+] VPN/Proxy lists updated: {len(self.vpn_ranges)} VPN ranges, {len(self.proxy_ips)} proxy IPs")
            return True
            
        except Exception as e:
            print(f"[-] Error updating VPN/Proxy lists: {e}")
            return False
    
    def update_datacenter_ranges(self) -> bool:
        """
        Load known datacenter IP ranges (AWS, Azure, GCP, etc.)
        Useful for detecting hosting IPs vs residential IPs.
        """
        try:
            # DigitalOcean example (they publish their ranges)
            dc_sources = [
                'https://www.cloudflare.com/ips-v4',
                'https://www.cloudflare.com/ips-v6'
            ]
            
            for url in dc_sources:
                try:
                    response = requests.get(url, timeout=10)
                    response.raise_for_status()
                    
                    for line in response.text.splitlines():
                        line = line.strip()
                        if line:
                            try:
                                ip_network(line, strict=False)
                                self.datacenter_ranges.add(line)
                            except ValueError:
                                continue
                except Exception:
                    continue
            
            print(f"[+] Datacenter ranges updated: {len(self.datacenter_ranges)} ranges")
            return True
            
        except Exception as e:
            print(f"[-] Error updating datacenter ranges: {e}")
            return False
    
    def load_geolocation_data(self):
        """
        Load IP to Country mapping - supports IPv4 and IPv6.
        """
        try:
            # IPv4 geolocation
            url_v4 = 'https://raw.githubusercontent.com/sapics/ip-location-db/main/geolite2-country/geolite2-country-ipv4.csv'
            response = requests.get(url_v4, timeout=15)
            response.raise_for_status()
            
            for line in response.text.splitlines():
                parts = line.split(',')
                if len(parts) >= 2:
                    ip_range = parts[0]
                    country = parts[1].strip('"')
                    self.ip_to_country[ip_range] = country
            
            # IPv6 geolocation
            url_v6 = 'https://raw.githubusercontent.com/sapics/ip-location-db/main/geolite2-country/geolite2-country-ipv6.csv'
            try:
                response = requests.get(url_v6, timeout=15)
                response.raise_for_status()
                
                for line in response.text.splitlines():
                    parts = line.split(',')
                    if len(parts) >= 2:
                        ip_range = parts[0]
                        country = parts[1].strip('"')
                        self.ip_to_country[ip_range] = country
            except Exception:
                pass
            
            print(f"[+] Geolocation data loaded: {len(self.ip_to_country)} entries (IPv4/IPv6)")
            return True
            
        except Exception as e:
            print(f"[-] Error loading geolocation data: {e}")
            return False
    
    def load_asn_data(self):
        """
        Load IP to ASN mapping - supports IPv4 and IPv6.
        """
        try:
            # IPv4 ASN
            url_v4 = 'https://raw.githubusercontent.com/sapics/ip-location-db/main/asn/asn-ipv4.csv'
            response = requests.get(url_v4, timeout=15)
            response.raise_for_status()
            
            for line in response.text.splitlines():
                parts = line.split(',')
                if len(parts) >= 2:
                    ip_range = parts[0]
                    try:
                        asn = int(parts[1].replace('AS', '').strip('"'))
                        self.ip_to_asn[ip_range] = asn
                    except ValueError:
                        continue
            
            # IPv6 ASN
            url_v6 = 'https://raw.githubusercontent.com/sapics/ip-location-db/main/asn/asn-ipv6.csv'
            try:
                response = requests.get(url_v6, timeout=15)
                response.raise_for_status()
                
                for line in response.text.splitlines():
                    parts = line.split(',')
                    if len(parts) >= 2:
                        ip_range = parts[0]
                        try:
                            asn = int(parts[1].replace('AS', '').strip('"'))
                            self.ip_to_asn[ip_range] = asn
                        except ValueError:
                            continue
            except Exception:
                pass
            
            print(f"[+] ASN data loaded: {len(self.ip_to_asn)} entries (IPv4/IPv6)")
            return True
            
        except Exception as e:
            print(f"[-] Error loading ASN data: {e}")
            return False
    
    def region_locker_ip(self, regions: List[str]):
        """
        Set regions to block. Uses ISO 3166-1 alpha-2 country codes.
        """
        self.blocked_regions = set(r.upper() for r in regions)
        print(f"[+] Region blocking enabled for: {', '.join(self.blocked_regions)}")
    
    def asn_blocker(self, asn_list: List[int]):
        """
        Set ASNs to block.
        """
        self.blocked_asns = set(asn_list)
        print(f"[+] ASN blocking enabled for: {', '.join(map(str, self.blocked_asns))}")
    
    def check_rate_limit(self, ip: str, max_requests: int = 100, 
                        time_window: int = 60, strict_mode: bool = False) -> tuple[bool, str]:
        """
        Check if IP exceeds rate limit.
        
        Args:
            ip: IP address to check
            max_requests: Maximum requests allowed
            time_window: Time window in seconds
            strict_mode: If True, permanently block after violations
        
        Returns:
            (is_blocked, reason) tuple
        """
        current_time = datetime.now()
        
        # Add current request
        self.ip_request_history[ip].append(current_time)
        
        # Remove old requests outside time window
        cutoff_time = current_time - timedelta(seconds=time_window)
        while self.ip_request_history[ip] and self.ip_request_history[ip][0] < cutoff_time:
            self.ip_request_history[ip].popleft()
        
        request_count = len(self.ip_request_history[ip])
        
        # Check if rate limit exceeded
        if request_count > max_requests:
            self.rate_limit_violations[ip] += 1
            
            if strict_mode and self.rate_limit_violations[ip] >= 3:
                return True, f"Rate limit exceeded: {request_count}/{max_requests} in {time_window}s (permanent block after 3 violations)"
            
            return True, f"Rate limit exceeded: {request_count}/{max_requests} in {time_window}s"
        
        return False, ""
    
    def is_tor_exit_node(self, ip: str) -> bool:
        """
        Check if IP is a Tor exit node (IPv4 or IPv6).
        """
        return ip in self.tor_exit_nodes
    
    def is_vpn_or_proxy(self, ip: str) -> tuple[bool, str]:
        """
        Check if IP is a VPN or proxy (IPv4 or IPv6).
        Returns (is_vpn_proxy, type) tuple.
        """
        try:
            ip_obj = ip_address(ip)
            
            # Check direct proxy match
            if ip in self.proxy_ips:
                return True, "proxy"
            
            # Check VPN ranges (CIDR)
            for vpn_range in self.vpn_ranges:
                try:
                    if '/' in vpn_range:
                        network = ip_network(vpn_range, strict=False)
                        if ip_obj in network:
                            return True, "vpn"
                    elif ip == vpn_range:
                        return True, "vpn"
                except ValueError:
                    continue
            
            # Check datacenter ranges (often used by VPNs)
            for dc_range in self.datacenter_ranges:
                try:
                    network = ip_network(dc_range, strict=False)
                    if ip_obj in network:
                        return True, "datacenter"
                except ValueError:
                    continue
            
            return False, ""
            
        except ValueError:
            return False, ""
    
    def is_malicious_pattern(self, ip: str) -> bool:
        """
        Check for malicious IP patterns - supports IPv4 and IPv6.
        """
        try:
            ip_obj = ip_address(ip)
            
            # Check for private/reserved ranges
            if ip_obj.is_private or ip_obj.is_reserved or ip_obj.is_loopback:
                return False
            
            # IPv4-specific checks
            if isinstance(ip_obj, IPv4Address):
                suspicious_patterns = [
                    r'^0\.', r'^10\.', 
                    r'^100\.(6[4-9]|[7-9]\d|1[0-1]\d|12[0-7])\.', 
                    r'^127\.', r'^169\.254\.', 
                    r'^172\.(1[6-9]|2\d|3[0-1])\.', 
                    r'^192\.0\.0\.', r'^192\.0\.2\.', r'^192\.168\.', 
                    r'^198\.1[8-9]\.', r'^198\.51\.100\.', 
                    r'^203\.0\.113\.', r'^22[4-9]\.', r'^2[3-4]\d\.',
                ]
                
                for pattern in suspicious_patterns:
                    if re.match(pattern, ip):
                        return True
                
                # Check for suspicious sequential patterns
                octets = ip.split('.')
                if len(set(octets)) == 1:
                    if ip not in ['8.8.8.8', '1.1.1.1']:
                        return True
            
            # IPv6-specific checks
            elif isinstance(ip_obj, IPv6Address):
                if ip_obj.is_link_local or ip_obj.is_site_local:
                    return True
                
                # Check for documentation/benchmark ranges
                doc_ranges = [
                    '2001:db8::/32',  # Documentation
                    'fc00::/7',        # Unique local
                    'fe80::/10',       # Link local
                    'ff00::/8',        # Multicast
                ]
                
                for range_str in doc_ranges:
                    try:
                        network = ip_network(range_str)
                        if ip_obj in network:
                            return True
                    except ValueError:
                        continue
            
            return False
            
        except ValueError:
            return True
    
    def get_country_for_ip(self, ip: str) -> Optional[str]:
        """
        Get country code for an IP address (IPv4 or IPv6).
        """
        try:
            ip_obj = ip_address(ip)
            for ip_range, country in self.ip_to_country.items():
                if '/' in ip_range:
                    network = ip_network(ip_range, strict=False)
                    if ip_obj in network:
                        return country
            return None
        except Exception:
            return None
    
    def get_asn_for_ip(self, ip: str) -> Optional[int]:
        """
        Get ASN for an IP address (IPv4 or IPv6).
        """
        try:
            ip_obj = ip_address(ip)
            for ip_range, asn in self.ip_to_asn.items():
                if '/' in ip_range:
                    network = ip_network(ip_range, strict=False)
                    if ip_obj in network:
                        return asn
            return None
        except Exception:
            return None
    
    def ip_checker(self, response,user_blocklist, ip_blocklist: Optional[Set[str]] = None, 
                   region_block: bool = False, regex_check: bool = True, 
                   asn_block: bool = False, rate_limit_check: bool = False,
                   max_requests: int = 100, time_window: int = 60,
                   block_tor: bool = False, block_vpn: bool = False,
                   block_proxy: bool = False, block_datacenter: bool = False) -> str:
        """
        Enhanced IP checker with rate limiting, Tor/VPN/Proxy detection, and IPv6 support.
        
        Args:
            response: List of IP addresses to check (IPv4 or IPv6)
            ip_blocklist: Optional custom blocklist
            region_block: Enable region-based blocking
            regex_check: Enable pattern matching
            asn_block: Enable ASN-based blocking
            rate_limit_check: Enable rate limiting
            max_requests: Max requests per time window
            time_window: Time window in seconds for rate limiting
            block_tor: Block Tor exit nodes
            block_vpn: Block VPN IPs
            block_proxy: Block proxy servers
            block_datacenter: Block datacenter IPs
        
        Returns:
            "BLOCKED" if any malicious IP found, "ALLOWED" otherwise
        """
        blocklist = ip_blocklist if ip_blocklist is not None else self.ip_blocklist
        
        for rdata in response:
            ip = str(rdata).strip()
            
            # Validate IP format (IPv4 or IPv6)
            try:
                ip_address(ip)
            except ValueError:
                print(f"[!] BLOCKED: {ip} (invalid IP format)")
                return "BLOCKED"
            
            # 1. Rate limiting check
            if rate_limit_check:
                is_rate_limited, reason = self.check_rate_limit(
                    ip, max_requests, time_window, strict_mode=True
                )
                if is_rate_limited:
                    print(f"[!] BLOCKED: {ip} ({reason})")
                    return "BLOCKED"
            
            # 2. Check against blocklist
            if ip in blocklist:
                print(f"[!] BLOCKED: {ip} (in threat feed blocklist)")
                return "BLOCKED"

            if ip in user_blocklist:
                print(f"[!] BLOCKED: {ip} (user blocked ip)")
                return "BLOCKED"
            
            # 3. Tor exit node check
            if block_tor and self.is_tor_exit_node(ip):
                print(f"[!] BLOCKED: {ip} (Tor exit node)")
                return "BLOCKED"
            
            # 4. VPN/Proxy detection
            is_vpn_proxy, vpn_type = self.is_vpn_or_proxy(ip)
            if is_vpn_proxy:
                if (block_vpn and vpn_type == "vpn") or \
                   (block_proxy and vpn_type == "proxy") or \
                   (block_datacenter and vpn_type == "datacenter"):
                    print(f"[!] BLOCKED: {ip} ({vpn_type} detected)")
                    return "BLOCKED"
            
            # 5. Check for malicious patterns
            if regex_check and self.is_malicious_pattern(ip):
                print(f"[!] BLOCKED: {ip} (suspicious pattern)")
                return "BLOCKED"
            
            # 6. Check region blocking
            if region_block and self.blocked_regions:
                country = self.get_country_for_ip(ip)
                if country and country in self.blocked_regions:
                    print(f"[!] BLOCKED: {ip} (region: {country})")
                    return "BLOCKED"
            
            # 7. Check ASN blocking
            if asn_block and self.blocked_asns:
                asn = self.get_asn_for_ip(ip)
                if asn and asn in self.blocked_asns:
                    print(f"[!] BLOCKED: {ip} (ASN: {asn})")
                    return "BLOCKED"
        
        return "ALLOWED"
    
    

def update_blocklist(ip_filter):
    ip_filter.update_blocklist()
    

def update_tor_nodes(ip_filter):
    ip_filter.update_tor_exit_nodes()
    
def update_vpn_proxy_lists(ip_filter):
    ip_filter.update_vpn_proxy_lists()
    
def update_datacenter_ranges(ip_filter):
    ip_filter.update_datacenter_ranges()
    
def update_geolocation_data(ip_filter):
    ip_filter.load_geolocation_data()
    ip_filter.load_asn_data()

