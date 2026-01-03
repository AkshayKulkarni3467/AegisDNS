import atexit
import threading
from dns_set_address import run_powershell_command, reset_dns_on_exit
from dns_divert import start_dns_divert
from dns_server import start_dns_server
import subprocess
import json
import time

def get_active_interface():
    """
    Get the active network interface. 
    Prioritizes non-virtual adapters, but falls back to any active adapter.
    """
    try:
        ps_command = '''
        Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | 
        Select-Object Name, InterfaceDescription, Virtual | 
        ConvertTo-Json
        '''
        
        output = subprocess.check_output(
            ['powershell', '-Command', ps_command], 
            text=True
        )
        
        interfaces = json.loads(output)
        
        if isinstance(interfaces, dict):
            interfaces = [interfaces]
        
        if not interfaces:
            print("No active interfaces found, defaulting to Wi-Fi")
            return "Wi-Fi"
        
        non_virtual = [i for i in interfaces if not i.get('Virtual', False)]
        
        if non_virtual:
            selected = non_virtual[0]['Name']
            print(f"Selected non-virtual adapter: {selected}")
            return selected
        
        selected = interfaces[0]['Name']
        print(f"Selected adapter (may be virtual): {selected}")
        return selected
        
    except json.JSONDecodeError as e:
        print(f"Failed to parse interface data: {e}")
        return "Wi-Fi"
    except subprocess.CalledProcessError as e:
        print(f"PowerShell command failed: {e}")
        return "Wi-Fi"
    except Exception as e:
        print(f"Failed to get active interface: {e}")
        return "Wi-Fi"

def get_all_active_interfaces():
    """
    Get all active interfaces for setting DNS on multiple adapters.
    Useful when both WiFi and mobile hotspot are active.
    """
    try:
        ps_command = '''
        Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | 
        Select-Object -ExpandProperty Name | 
        ConvertTo-Json
        '''
        
        output = subprocess.check_output(
            ['powershell', '-Command', ps_command], 
            text=True
        )
        
        interfaces = json.loads(output)
        
        if isinstance(interfaces, str):
            return [interfaces]
        return interfaces if interfaces else ["Wi-Fi"]
        
    except Exception as e:
        print(f"Failed to get all interfaces: {e}")
        return ["Wi-Fi"]

def setup_firewall_rules(log_func):
    """
    Setup Windows Firewall rules for DNS filter.
    Removes existing rules first to avoid duplicates.
    """
    rules = [
        {
            "name": "DNS Filter Local Inbound",
            "direction": "Inbound",
            "port": "6667"
        },
        {
            "name": "DNS Filter Local Outbound",
            "direction": "Outbound",
            "port": "6667"
        },
        {
            "name": "DNS Filter DNS Port",
            "direction": "Inbound",
            "port": "53"
        }
    ]
    
    for rule in rules:
        remove_command = f'Remove-NetFirewallRule -DisplayName "{rule["name"]}" -ErrorAction SilentlyContinue'
        try:
            subprocess.run(
                ['powershell', '-Command', remove_command],
                capture_output=True,
                text=True,
                timeout=5
            )
        except Exception:
            pass 
        
        create_command = f'''
        New-NetFirewallRule -DisplayName "{rule["name"]}" `
            -Direction {rule["direction"]} `
            -Protocol UDP `
            -LocalPort {rule["port"]} `
            -Action Allow `
            -ErrorAction Stop
        '''
        
        try:
            result = subprocess.run(
                ['powershell', '-Command', create_command],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                log_func(f"Firewall rule created: {rule['name']}")
            else:
                log_func(f"Warning: Could not create firewall rule '{rule['name']}': {result.stderr}")
                
        except subprocess.TimeoutExpired:
            log_func(f"Timeout creating firewall rule: {rule['name']}")
        except Exception as e:
            log_func(f"Error creating firewall rule '{rule['name']}': {e}")

def remove_firewall_rules(log_func):
    """
    Remove the firewall rules created by setup_firewall_rules.
    Called during cleanup.
    """
    rule_names = [
        "DNS Filter Local Inbound",
        "DNS Filter Local Outbound",
        "DNS Filter DNS Port"
    ]
    
    for rule_name in rule_names:
        remove_command = f'Remove-NetFirewallRule -DisplayName "{rule_name}" -ErrorAction SilentlyContinue'
        try:
            subprocess.run(
                ['powershell', '-Command', remove_command],
                capture_output=True,
                text=True,
                timeout=5
            )
            log_func(f"Firewall rule removed: {rule_name}")
        except Exception as e:
            log_func(f"Note: Could not remove firewall rule '{rule_name}': {e}")

dns_server_thread = None
dns_divert_thread = None
is_running = False

def flush_all_caches(log_func):
    """
    Comprehensive cache flushing including Windows DNS, NetBIOS, and ARP.
    """
    log_func("Performing comprehensive cache flush...")
    
    try:
        result = subprocess.run(['ipconfig', '/flushdns'], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            log_func("✓ Windows DNS cache flushed")
        else:
            log_func(f"⚠ DNS cache flush warning: {result.stderr}")
    except Exception as e:
        log_func(f"✗ Failed to flush DNS cache: {e}")
    
    try:
        subprocess.run(['nbtstat', '-R'], capture_output=True, timeout=10)
        subprocess.run(['nbtstat', '-RR'], capture_output=True, timeout=10)
        log_func("✓ NetBIOS cache reset")
    except Exception as e:
        log_func(f"⚠ NetBIOS reset warning: {e}")
    
    try:
        subprocess.run(['net', 'stop', 'dnscache'], capture_output=True, timeout=5)
        time.sleep(0.5)
        subprocess.run(['net', 'start', 'dnscache'], capture_output=True, timeout=5)
        log_func("✓ DNS Client service restarted")
    except Exception as e:
        log_func(f"⚠ DNS service restart warning: {e}")
    
    log_func("Cache flush complete. Please restart your browser for best results.")

def flush_dns_cache(log_func):
    """
    Flush the Windows DNS cache to prevent cached lookups from bypassing the filter.
    """
    try:
        result = subprocess.run(
            ['ipconfig', '/flushdns'],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            log_func("DNS cache flushed successfully")
        else:
            log_func(f"Warning: Could not flush DNS cache: {result.stderr}")
    except Exception as e:
        log_func(f"Error flushing DNS cache: {e}")

def start_filter(log_func):
    global dns_server_thread, dns_divert_thread, is_running
    if is_running:
        return
    
    atexit.register(reset_dns_on_exit)
    
    log_func("Flushing all system caches...")
    flush_all_caches(log_func)
    
    log_func("Setting up firewall rules...")
    setup_firewall_rules(log_func)
    
    active_interfaces = get_all_active_interfaces()
    
    log_func(f"Setting DNS on interfaces: {', '.join(active_interfaces)}")
    
    dns_set_success = False
    for iface in active_interfaces:
        set_dns_command = f'Set-DnsClientServerAddress -InterfaceAlias "{iface}" -ServerAddresses ("127.0.0.1")'
        try:
            run_powershell_command(set_dns_command)
            log_func(f"DNS set to 127.0.0.1 on {iface}")
            dns_set_success = True
        except Exception as e:
            log_func(f"Failed to set DNS on {iface}: {e}")
    
    if not dns_set_success:
        log_func("Failed to set DNS on any interface!")
        return
    
    try:
        dns_server_thread = threading.Thread(target=start_dns_server, args=(log_func,), daemon=True)
        dns_divert_thread = threading.Thread(target=start_dns_divert, daemon=True)

        dns_server_thread.start()
        dns_divert_thread.start()
        is_running = True
        log_func("All components are running. Dashboard is active.")
        
    except Exception as e:
        log_func(f"An error occurred: {e}")
        reset_dns_on_exit()

def stop_filter(log_func):
    global is_running
    
    if not is_running:
        return
    is_running = False
    log_func("Stopping DNS filter...")
    reset_dns_on_exit()
    
    log_func("Removing firewall rules...")
    remove_firewall_rules(log_func)
    
    log_func("DNS settings have been reset.")