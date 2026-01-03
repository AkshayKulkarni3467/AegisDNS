import socket
import json
import os
import re
import sqlite3
import time
from dnslib import DNSRecord, DNSHeader, RCODE, QTYPE
import dns.resolver
from dns_utils import log_request, load_dns_blocklist, load_ip_blocklist
from dns_model import load_model, predict_domain
from ip_model import IPFilterSystem

DNS_BLOCKLIST_FILE = "manual_lists/domain_blocklist.txt"
IP_BLOCKLIST_FILE = "manual_lists/ip_blocklist.txt"
WHITELIST_FILE = "manual_lists/domain_whitelist.txt"
FILTER_CONFIG_PATH = "filter_config.json"
DNS_CACHE_DB = "dns_cache.db"

# Major legitimate domains whitelist
LEGITIMATE_DOMAINS_WHITELIST = {
    # Major tech companies
    'google.com', 'youtube.com', 'gmail.com', 'googlevideo.com', 'gstatic.com',
    'microsoft.com', 'bing.com', 'msn.com', 'live.com', 'office.com', 'msedge.net',
    'windows.com', 'windowsupdate.com', 'azure.com', 'skype.com', 'xbox.com',
    'facebook.com', 'instagram.com', 'whatsapp.com', 'messenger.com', 'fbcdn.net',
    'apple.com', 'icloud.com', 'apple-dns.net', 'cdn-apple.com',
    'amazon.com', 'amazonaws.com', 'aws.com', 'cloudfront.net',
    'twitter.com', 'twimg.com', 'x.com',
    'linkedin.com', 'licdn.com',
    'netflix.com', 'nflxvideo.net', 'nflximg.net',
    'cloudflare.com', 'cloudflare-dns.com',
    'reddit.com', 'redd.it', 'redditstatic.com',
    'github.com', 'githubusercontent.com', 'github.io',
    'stackoverflow.com', 'stackexchange.com',
    'wikipedia.org', 'wikimedia.org',
    'zoom.us', 'zoom.com',
    'dropbox.com', 'dropboxusercontent.com',
    'spotify.com', 'scdn.co',
    'paypal.com', 'paypal-mktg.com',
    'ebay.com', 'ebaystatic.com',
    'yahoo.com', 'yimg.com',
}

# Don't load at import time - load lazily
model = None
feature_extractor = None
filter_config = None
manual_whitelist = set()

resolver = dns.resolver.Resolver()
ip_filter = IPFilterSystem()


class DNSCache:
    """SQLite-based DNS cache with automatic expiration"""
    
    def __init__(self, db_path=DNS_CACHE_DB):
        self.db_path = db_path
        self.conn = None
        self._init_db()
    
    def _init_db(self):
        """Initialize the database and create tables if they don't exist"""
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS dns_cache (
                domain TEXT PRIMARY KEY,
                dns_record BLOB NOT NULL,
                cached_time REAL NOT NULL,
                ttl INTEGER NOT NULL,
                expires_at REAL NOT NULL
            )
        ''')
        self.conn.execute('''
            CREATE INDEX IF NOT EXISTS idx_expires_at 
            ON dns_cache(expires_at)
        ''')
        self.conn.commit()
        
        # Clean up expired entries on initialization
        self._cleanup_expired()
    
    def _cleanup_expired(self):
        """Remove expired cache entries"""
        current_time = time.time()
        self.conn.execute(
            'DELETE FROM dns_cache WHERE expires_at < ?',
            (current_time,)
        )
        self.conn.commit()
    
    def get(self, domain):
        """
        Retrieve a cached DNS record if it exists and hasn't expired.
        Returns: (cached_time, dns_record) or None if not found/expired
        """
        current_time = time.time()
        
        cursor = self.conn.execute(
            'SELECT dns_record, cached_time, expires_at FROM dns_cache WHERE domain = ?',
            (domain,)
        )
        row = cursor.fetchone()
        
        if row is None:
            return None
        
        dns_record_bytes, cached_time, expires_at = row
        
        # Check if expired
        if current_time >= expires_at:
            self.delete(domain)
            return None
        
        # Deserialize the DNS record
        try:
            dns_record = DNSRecord.parse(dns_record_bytes)
            return (cached_time, dns_record)
        except Exception:
            # If deserialization fails, delete the corrupted entry
            self.delete(domain)
            return None
    
    def set(self, domain, dns_record, ttl):
        """
        Store a DNS record in the cache.
        
        Args:
            domain: Domain name
            dns_record: DNSRecord object
            ttl: Time-to-live in seconds
        """
        cached_time = time.time()
        expires_at = cached_time + ttl
        
        # Serialize the DNS record
        dns_record_bytes = dns_record.pack()
        
        self.conn.execute('''
            INSERT OR REPLACE INTO dns_cache (domain, dns_record, cached_time, ttl, expires_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (domain, dns_record_bytes, cached_time, ttl, expires_at))
        self.conn.commit()
    
    def delete(self, domain):
        """Delete a specific domain from the cache"""
        self.conn.execute('DELETE FROM dns_cache WHERE domain = ?', (domain,))
        self.conn.commit()
    
    def clear_all(self):
        """Clear all cache entries"""
        self.conn.execute('DELETE FROM dns_cache')
        self.conn.commit()
    
    def get_stats(self):
        """Get cache statistics"""
        cursor = self.conn.execute('SELECT COUNT(*) FROM dns_cache')
        total = cursor.fetchone()[0]
        
        current_time = time.time()
        cursor = self.conn.execute(
            'SELECT COUNT(*) FROM dns_cache WHERE expires_at < ?',
            (current_time,)
        )
        expired = cursor.fetchone()[0]
        
        return {
            'total_entries': total,
            'expired_entries': expired,
            'valid_entries': total - expired
        }
    
    def close(self):
        """Close the database connection"""
        if self.conn:
            self.conn.close()


# Initialize the cache
dns_cache = DNSCache()


def load_filter_config():
    """Load filter configuration"""
    if os.path.exists(FILTER_CONFIG_PATH):
        try:
            with open(FILTER_CONFIG_PATH, 'r') as f:
                return json.load(f)
        except:
            pass
    # Default config with all methods enabled
    return {
        "use_whitelist": True,
        "use_manual_list": True,
        "use_ip_check": True,
        "use_punycode_check": True,
        "use_excessive_hyphens": True,
        "use_long_label": True,
        "use_hex_string": True,
        "use_suspicious_tld": True,
        "use_dga_pattern": True,
        "use_ml_model": True,
        "ml_threshold": 0.85,
        "suspicious_tld_threshold": 0.6
    }


def load_manual_whitelist():
    """Load manual whitelist from file"""
    whitelist = set()
    if os.path.exists(WHITELIST_FILE):
        try:
            with open(WHITELIST_FILE, 'r') as f:
                for line in f:
                    domain = line.strip().lower()
                    if domain and not domain.startswith('#'):
                        whitelist.add(domain)
        except:
            pass
    return whitelist


def is_whitelisted_domain(domain, manual_whitelist):
    """Check if domain or its parent is whitelisted"""
    domain = domain.lower().rstrip('.')
    
    # Check built-in whitelist
    if domain in LEGITIMATE_DOMAINS_WHITELIST:
        return True, "whitelist:builtin"
    
    # Check manual whitelist
    if domain in manual_whitelist:
        return True, "whitelist:manual"
    
    # Check parent domains (for subdomains)
    parts = domain.split('.')
    for i in range(len(parts)):
        parent = '.'.join(parts[i:])
        if parent in LEGITIMATE_DOMAINS_WHITELIST:
            return True, "whitelist:builtin_parent"
        if parent in manual_whitelist:
            return True, "whitelist:manual_parent"
    
    return False, ""


def _ensure_model_loaded():
    """Lazy load the model on first use"""
    global model, feature_extractor, filter_config, manual_whitelist
    if model is None:
        model, feature_extractor = load_model()
    if filter_config is None:
        filter_config = load_filter_config()
    if not manual_whitelist:
        manual_whitelist = load_manual_whitelist()


def check_heuristics(domain, config):
    """Check domain against all enabled heuristics"""
    
    # 1. Direct IP address check
    if config.get("use_ip_check", True):
        if re.search(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
            return True, 0.99, "heuristic:ip_address"
    
    # 2. Punycode check
    if config.get("use_punycode_check", True):
        if 'xn--' in domain:
            return True, 0.98, "heuristic:punycode"
    
    # 3. Excessive hyphens
    if config.get("use_excessive_hyphens", True):
        if domain.count('-') > 3:
            return True, 0.95, "heuristic:excessive_hyphens"
    
    # 4. Very long subdomain labels
    if config.get("use_long_label", True):
        labels = domain.split('.')
        if any(len(label) > 30 for label in labels):
            return True, 0.94, "heuristic:long_label"
    
    # 5. Random-looking hex strings
    if config.get("use_hex_string", True):
        if re.search(r'[0-9a-f]{32,}', domain):
            return True, 0.96, "heuristic:hex_string"
    
    # 6. DGA-like patterns (alternating consonants/vowels)
    if config.get("use_dga_pattern", True):
        consonants = set('bcdfghjklmnpqrstvwxyz')
        vowels = set('aeiou')
        labels = domain.split('.')
        main_label = labels[0] if labels else ''
        
        if len(main_label) > 10:
            alternations = 0
            for i in range(len(main_label) - 1):
                curr_is_vowel = main_label[i] in vowels
                next_is_vowel = main_label[i+1] in vowels
                if curr_is_vowel != next_is_vowel:
                    alternations += 1
            
            if alternations > len(main_label) * 0.7:
                return True, 0.93, "heuristic:dga_pattern"
    
    return False, 0.0, ""


def check_suspicious_tld(domain, config):
    """Check if domain uses a suspicious TLD"""
    if not config.get("use_suspicious_tld", True):
        return False, 0.0
    
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc', '.ws', '.top', '.xyz']
    
    for tld in suspicious_tlds:
        if domain.endswith(tld):
            # Return modified threshold for ML model
            return True, config.get("suspicious_tld_threshold", 0.6)
    
    return False, 0.0


def dns_action_with_config(qname, model, feature_extractor, blocklist, manual_whitelist, config):
    """Make DNS decision based on configuration"""
    qname = qname.strip().lower().rstrip(".")
    
    # Check whitelist first (highest priority)
    if config.get("use_whitelist", True):
        is_whitelisted, reason = is_whitelisted_domain(qname, manual_whitelist)
        if is_whitelisted:
            return {
                "domain": qname,
                "decision": "ALLOWED",
                "score": 0.0,
                "reason": reason
            }
    
    # Check manual blocklist
    if config.get("use_manual_list", True):
        if qname in blocklist:
            return {
                "domain": qname,
                "decision": "BLOCKED",
                "score": 1.00,
                "reason": "blocklist:manual"
            }
    
    # Check heuristics
    is_malicious, score, reason = check_heuristics(qname, config)
    if is_malicious:
        return {
            "domain": qname,
            "decision": "BLOCKED",
            "score": score,
            "reason": reason
        }
    
    # Check for suspicious TLD (affects ML threshold)
    has_suspicious_tld, modified_threshold = check_suspicious_tld(qname, config)
    ml_threshold = modified_threshold if has_suspicious_tld else config.get("ml_threshold", 0.85)
    
    # ML model prediction (if enabled)
    if config.get("use_ml_model", True):
        try:
            score = predict_domain(qname, model, feature_extractor)
            
            if score >= ml_threshold:
                decision = "BLOCKED"
                reason = f"ml:malicious{':suspicious_tld' if has_suspicious_tld else ''}"
            elif score >= 0.65:
                decision = "FLAGGED"
                reason = f"ml:suspicious{':suspicious_tld' if has_suspicious_tld else ''}"
            else:
                decision = "ALLOWED"
                reason = "ml:benign"
            
            return {
                "domain": qname,
                "decision": decision,
                "score": float(score),
                "reason": reason
            }
        except Exception as e:
            # Fallback to allow if ML fails
            return {
                "domain": qname,
                "decision": "ALLOWED",
                "score": 0.0,
                "reason": "error:ml_failed"
            }
    
    # If all methods disabled, allow by default
    return {
        "domain": qname,
        "decision": "ALLOWED",
        "score": 0.0,
        "reason": "no_filters_enabled"
    }


def ip_checker(response, ip_blocklist):
    blocked_ip_found = False
    for rdata in response:
        if str(rdata) in ip_blocklist:
            blocked_ip_found = True
            break
    if blocked_ip_found:
        return "BLOCKED"
    else:
        return "ALLOWED"
        

def quarantine_check(reply):
    pass


def handle_dns_query(data, addr, sock, log_func, is_quarantine_check=False): 
    global model, feature_extractor, filter_config, manual_whitelist
    _ensure_model_loaded()
    
    client_ip, client_port = addr
    ip_a = "ALLOWED"
    try:
        request = DNSRecord.parse(data)
    except Exception as e:
        log_func(f"Failed to parse DNS packet from {client_ip}:{client_port}: {e}")
        return

    qname = str(request.q.qname).rstrip(".").lower()
    dns_blocklist = load_dns_blocklist(DNS_BLOCKLIST_FILE)
    ip_blocklist = load_ip_blocklist(IP_BLOCKLIST_FILE)

    if not is_quarantine_check:
        # Try to get from SQLite cache
        cached_result = dns_cache.get(qname)
        if cached_result is not None:
            cached_time, cached_record = cached_result
            action = "CACHED"
            reply = cached_record
            reply.header.id = request.header.id
            log_request(client_ip, client_port, qname, action, log_func) 
            try:
                sock.sendto(reply.pack(), addr)
            except OSError as e:
                log_func(f"Failed to send cached response to {client_ip}:{client_port}: {e}")
            return
    
    # Use config-aware DNS action with all methods
    dns_a = dns_action_with_config(qname, model, feature_extractor, dns_blocklist, manual_whitelist, filter_config)
    
    if dns_a["decision"] == "BLOCKED":
        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, ra=1, rcode=RCODE.NXDOMAIN))
        reply.add_question(request.q)
    else:
        reply = None
        try:
            response = resolver.resolve(qname, rdtype=QTYPE.A)
            
            quarantine_check_result = quarantine_check(reply)
            
                
            ip_a = ip_filter.ip_checker(
                response, 
                ip_blocklist,
                ip_blocklist=ip_filter.ip_blocklist,
                region_block=filter_config.get("ip_region_block", False),
                regex_check=filter_config.get("ip_regex_check", True),
                asn_block=filter_config.get("ip_asn_block", False),
                rate_limit_check=filter_config.get("ip_rate_limit_check", False),
                max_requests=filter_config.get("ip_max_requests", 100),
                time_window=filter_config.get("ip_time_window", 60),
                block_tor=filter_config.get("ip_block_tor", False),
                block_vpn=filter_config.get("ip_block_vpn", False),
                block_proxy=filter_config.get("ip_block_proxy", False),
                block_datacenter=filter_config.get("ip_block_datacenter", False)
            )

            
            if ip_a == "BLOCKED":
                action = "IP BLOCKED"
                reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, ra=1, rcode=RCODE.NXDOMAIN))
                reply.add_question(request.q)
            else:
                wire_data = response.response.to_wire()
                reply = DNSRecord.parse(wire_data)
                reply.header.id = request.header.id
                
                # Calculate TTL and cache the response
                min_ttl = min([r.ttl for r in reply.rr]) if reply.rr else 300  # Default 5 min
                dns_cache.set(qname, reply, min_ttl)
                
        except Exception as e:
            action = f"FAILED ({e})"
            reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, ra=1, rcode=RCODE.SERVFAIL))

    log_request(client_ip, client_port, qname, f'A : {dns_a["decision"]} ; R : {dns_a["reason"]} ; S : {dns_a["score"]:.3f} ; IP : {ip_a}', log_func) 
    
    if reply:
        try:
            sock.sendto(reply.pack(), addr)
        except OSError as e:
            log_func(f"Socket error sending reply to {client_ip}:{client_port}: {e}")
            

def start_dns_server(log_func, listen_ip="0.0.0.0", listen_port=6667, upstream_dns="8.8.8.8"):
    _ensure_model_loaded()
    
    # Log the current configuration
    enabled_methods = [k for k, v in filter_config.items() if isinstance(v, bool) and v]
    log_func(f"Filter configuration loaded: {len(enabled_methods)} methods enabled")
    log_func(f"ML Threshold: {filter_config.get('ml_threshold', 0.85):.2f}")
    
    # Log cache statistics
    stats = dns_cache.get_stats()
    log_func(f"DNS Cache initialized: {stats['valid_entries']} valid entries")
    
    LISTEN_IP = listen_ip 
    LISTEN_PORT = listen_port
    UPSTREAM_DNS = upstream_dns

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [UPSTREAM_DNS]
    resolver.timeout = 3
    resolver.lifetime = 3

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
    except OSError:
        pass 
    
    sock.settimeout(1.0)
    
    sock.bind((LISTEN_IP, LISTEN_PORT))
    log_func(f"DNS Filter running on {LISTEN_IP}:{LISTEN_PORT}")
    
    try:
        while True:
            try:
                data, addr = sock.recvfrom(512)
                handle_dns_query(data, addr, sock, log_func)
            except socket.timeout:
                continue
            except OSError as e:
                if hasattr(e, 'winerror') and e.winerror == 10054:
                    log_func(f"Connection reset by peer - continuing...")
                else:
                    log_func(f"Socket error: {e}")
                continue
            except Exception as e:
                log_func(f"Error handling packet: {e}")
                continue
    finally:
        # Clean up on shutdown
        dns_cache.close()
        log_func("DNS server shutting down, cache closed")