from datetime import datetime
# Add to dns_utils.py or create as whitelist_utils.py

import os

WHITELIST_FILE = "manual_lists/domain_whitelist.txt"

def load_whitelist(filepath=WHITELIST_FILE):
    """Load whitelist from file"""
    whitelist = set()
    if os.path.exists(filepath):
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    domain = line.strip().lower()
                    if domain and not domain.startswith('#'):
                        whitelist.add(domain)
        except Exception as e:
            print(f"Error loading whitelist: {e}")
    return whitelist


def save_whitelist(filepath, whitelist):
    """Save whitelist to file"""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("# Whitelisted domains - one per line\n")
            f.write("# Subdomains of whitelisted domains are also allowed\n")
            f.write("# Example: google.com (allows mail.google.com, drive.google.com, etc.)\n\n")
            for domain in sorted(whitelist):
                f.write(f"{domain}\n")
    except Exception as e:
        print(f"Error saving whitelist: {e}")


def add_to_whitelist(domain, filepath=WHITELIST_FILE):
    """Add a domain to the whitelist"""
    whitelist = load_whitelist(filepath)
    whitelist.add(domain.strip().lower())
    save_whitelist(filepath, whitelist)


def remove_from_whitelist(domain, filepath=WHITELIST_FILE):
    """Remove a domain from the whitelist"""
    whitelist = load_whitelist(filepath)
    whitelist.discard(domain.strip().lower())
    save_whitelist(filepath, whitelist)

def load_dns_blocklist(blocklist_file):
    try:
        with open(blocklist_file, "r", encoding="utf-8") as f:
            return set(line.strip().lower() for line in f if line.strip())
    except FileNotFoundError:
        return set()
    
def load_ip_blocklist(blocklist_file):
    try:
        with open(blocklist_file, "r", encoding="utf-8") as f:
            return set(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        return set()

def log_request(client_ip, client_port, domain, action, log_func):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {client_ip}:{client_port} -> Query: {domain} | Action: {action}"
    
    log_func(log_entry)
    
    print(log_entry)
    
    with open("dns_filter.log", "a", encoding="utf-8") as logfile:
        logfile.write(log_entry + "\n")
        
def save_blocklist(blocklist_file, entries):
    """Saves a set of entries back to a file."""
    with open(blocklist_file, "w", encoding="utf-8") as f:
        for entry in sorted(list(entries)):
            f.write(entry + "\n")