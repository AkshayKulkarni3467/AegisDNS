from datetime import datetime

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