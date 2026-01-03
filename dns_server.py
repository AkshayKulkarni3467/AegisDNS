# dns_server.py
import socket
from dnslib import DNSRecord, DNSHeader, RCODE, QTYPE
import dns.resolver
from dns_utils import log_request, load_dns_blocklist, load_ip_blocklist
from dns_model import dns_action, load_model
from ip_model import IPFilterSystem
import time

DNS_BLOCKLIST_FILE = "domain_blocklist.txt"
IP_BLOCKLIST_FILE = "ip_blocklist.txt"

# Don't load at import time - load lazily
model = None
feature_extractor = None

resolver = dns.resolver.Resolver()
dns_cache = {}
ip_filter = IPFilterSystem()


def _ensure_model_loaded():
    """Lazy load the model on first use"""
    global model, feature_extractor
    if model is None:
        model, feature_extractor = load_model()


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
    global model, feature_extractor
    _ensure_model_loaded()  # Load model if not already loaded
    
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
        if qname in dns_cache:
            cached_time, cached_record = dns_cache[qname]
            min_ttl = min([r.ttl for r in cached_record.rr]) if cached_record.rr else 0
            
            if (time.time() - cached_time) < min_ttl:
                action = "CACHED"
                reply = cached_record
                reply.header.id = request.header.id
                log_request(client_ip, client_port, qname, action, log_func) 
                try:
                    sock.sendto(reply.pack(), addr)
                except OSError as e:
                    log_func(f"Failed to send cached response to {client_ip}:{client_port}: {e}")
                return
            else:
                del dns_cache[qname]
    
    dns_a = dns_action(qname, model, feature_extractor, blocklist=dns_blocklist, ml_threshold=0.7)
    
    if dns_a["decision"] == "BLOCKED":
        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, ra=1, rcode=RCODE.NXDOMAIN))
        reply.add_question(request.q)
    else:
        reply = None
        try:
            response = resolver.resolve(qname, rdtype=QTYPE.A)
            
            quarantine_check_result = quarantine_check(reply)
            
                
            ip_a = ip_filter.ip_checker(response, ip_blocklist)

            
            if ip_a == "BLOCKED":
                action = "IP BLOCKED"
                reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, ra=1, rcode=RCODE.NXDOMAIN))
                reply.add_question(request.q)
            else:
                wire_data = response.response.to_wire()
                reply = DNSRecord.parse(wire_data)
                reply.header.id = request.header.id
                dns_cache[qname] = (time.time(), reply)
                
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
    _ensure_model_loaded()  # Load model when server starts
    
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
    
    while True:
        try:
            data, addr = sock.recvfrom(512)
            handle_dns_query(data, addr, sock, log_func)
        except socket.timeout:
            continue
        except OSError as e:
            if e.winerror == 10054:
                log_func(f"Connection reset by peer - continuing...")
            else:
                log_func(f"Socket error: {e}")
            continue
        except Exception as e:
            log_func(f"Error handling packet: {e}")
            continue