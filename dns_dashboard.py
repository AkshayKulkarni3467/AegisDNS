import flet as ft
import threading
import time
import json
import os
import dns_controller
from dns_utils import load_dns_blocklist, load_ip_blocklist, save_blocklist

# Add whitelist functions
def load_whitelist(filepath="manual_lists/domain_whitelist.txt"):
    """Load whitelist from file"""
    whitelist = set()
    if os.path.exists(filepath):
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    domain = line.strip().lower()
                    if domain and not domain.startswith('#'):
                        whitelist.add(domain)
        except:
            pass
    return whitelist

def save_whitelist(filepath, whitelist):
    """Save whitelist to file"""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write("# Whitelisted domains - one per line\n")
        f.write("# Subdomains are also allowed\n\n")
        for domain in sorted(whitelist):
            f.write(f"{domain}\n")
from dns_model import incremental_update
from ip_model import IPFilterSystem

# Global state
is_filter_running = False
ip_filter = IPFilterSystem()

# Configuration file for filter settings
FILTER_CONFIG_PATH = "filter_config.json"

# Default filter configuration
default_filter_config = {
    # DNS Core methods
    "use_whitelist": True,
    "use_manual_list": True,
    
    # DNS Heuristic methods
    "use_ip_check": True,
    "use_punycode_check": True,
    "use_excessive_hyphens": True,
    "use_long_label": True,
    "use_hex_string": True,
    "use_suspicious_tld": True,
    "use_dga_pattern": True,
    
    # DNS ML method
    "use_ml_model": True,
    
    # DNS Thresholds
    "ml_threshold": 0.85,
    "suspicious_tld_threshold": 0.6,
    
    # IP Filter methods
    "ip_use_blocklist": True,
    "ip_region_block": False,
    "ip_regex_check": True,
    "ip_asn_block": False,
    "ip_rate_limit_check": False,
    "ip_block_tor": False,
    "ip_block_vpn": False,
    "ip_block_proxy": False,
    "ip_block_datacenter": False,
    
    # IP Rate limiting
    "ip_max_requests": 100,
    "ip_time_window": 60
}

# UI Components that need global access
log_viewer_container = ft.Column(controls=[], scroll="auto", expand=True)
domain_items_column = ft.Column(controls=[], scroll="auto", expand=True)
ip_items_column = ft.Column(controls=[], scroll="auto", expand=True)
whitelist_items_column = ft.Column(controls=[], scroll="auto", expand=True)


def load_filter_config():
    """Load filter configuration from file"""
    if os.path.exists(FILTER_CONFIG_PATH):
        try:
            with open(FILTER_CONFIG_PATH, 'r') as f:
                return json.load(f)
        except:
            pass
    return default_filter_config.copy()


def save_filter_config(config):
    """Save filter configuration to file"""
    with open(FILTER_CONFIG_PATH, 'w') as f:
        json.dump(config, f, indent=2)


def main(page: ft.Page):
    global is_filter_running

    page.title = "DNS Filter Dashboard"
    page.window_width = 1200
    page.window_height = 750
    page.padding = 0
    page.theme_mode = ft.ThemeMode.DARK

    # Load current filter config
    filter_config = load_filter_config()

    # ==================== Utility Functions ====================
    
    def load_initial_logs():
        """Load the last 50 logs from file"""
        try:
            with open("dns_filter.log", "r", encoding="utf-8") as f:
                logs = f.readlines()
                for log in logs[-50:]:
                    log_text = log.strip()
                    add_log_to_ui(log_text, update_page=False)
        except FileNotFoundError:
            log_viewer_container.controls.append(
                ft.Text("No previous logs found.", size=12, color="grey")
            )
        page.update()

    def add_log_to_ui(message, update_page=True):
        """Add a log message to the UI with appropriate coloring"""
        color = "white"
        if "BLOCKED" in message:
            color = "red"
        elif "ALLOWED" in message:
            color = "green"
        elif "CACHED" in message:
            color = "yellow"
        elif "FAILED" in message:
            color = "orange"
        elif "✓" in message:
            color = "lightgreen"
        elif "✗" in message or "⚠" in message:
            color = "orange"

        log_viewer_container.controls.insert(
            0, 
            ft.Container(
                content=ft.Text(message, size=11, color=color, selectable=True),
                padding=ft.padding.symmetric(vertical=2, horizontal=5)
            )
        )
        
        # Keep only last 100 logs in memory
        if len(log_viewer_container.controls) > 100:
            del log_viewer_container.controls[-1]
        
        if update_page:
            page.update()

    def update_blocklist_display():
        """Refresh the blocklist and whitelist displays"""
        domain_items_column.controls.clear()
        ip_items_column.controls.clear()
        whitelist_items_column.controls.clear()

        domains = sorted(list(load_dns_blocklist("manual_lists/domain_blocklist.txt")))
        if not domains:
            domain_items_column.controls.append(
                ft.Text("No domains blocked.", color="grey", size=12)
            )
        else:
            for domain in domains:
                domain_items_column.controls.append(
                    ft.Container(
                        content=ft.Text(domain, size=12),
                        padding=5,
                        border_radius=5,
                        bgcolor="#2C2C2C"
                    )
                )

        ips = sorted(list(load_ip_blocklist("manual_lists/ip_blocklist.txt")))
        if not ips:
            ip_items_column.controls.append(
                ft.Text("No IPs blocked.", color="grey", size=12)
            )
        else:
            for ip in ips:
                ip_items_column.controls.append(
                    ft.Container(
                        content=ft.Text(ip, size=12),
                        padding=5,
                        border_radius=5,
                        bgcolor="#2C2C2C"
                    )
                )
        
        # Whitelist display
        whitelisted = sorted(list(load_whitelist("manual_lists/domain_whitelist.txt")))
        if not whitelisted:
            whitelist_items_column.controls.append(
                ft.Text("No domains whitelisted.", color="grey", size=12)
            )
        else:
            for domain in whitelisted:
                whitelist_items_column.controls.append(
                    ft.Container(
                        content=ft.Text(domain, size=12, color="lightgreen"),
                        padding=5,
                        border_radius=5,
                        bgcolor="#2C2C2C"
                    )
                )
        
        domain_items_column.update()
        ip_items_column.update()
        whitelist_items_column.update()

    # ==================== Tab 1: Control Panel ====================
    
    status_indicator = ft.Container(
        width=12,
        height=12,
        border_radius=6,
        bgcolor="red"
    )
    
    status_text = ft.Text("Stopped", size=14, weight=ft.FontWeight.BOLD)
    
    start_stop_button = ft.ElevatedButton(
        text="Start Filter",
        icon=ft.Icons.PLAY_ARROW,
        bgcolor="#1B5E20",
        color="white",
        width=200,
        height=50
    )

    def start_stop_filter(e):
        global is_filter_running
        if not is_filter_running:
            # Start filter
            filter_thread = threading.Thread(
                target=dns_controller.start_filter, 
                args=(add_log_to_ui,), 
                daemon=True
            )
            filter_thread.start()
            
            start_stop_button.text = "Stop Filter"
            start_stop_button.icon = ft.Icons.STOP
            start_stop_button.bgcolor = "#B71C1C"
            status_text.value = "Running"
            status_indicator.bgcolor = "green"
            is_filter_running = True
        else:
            # Stop filter
            dns_controller.stop_filter(add_log_to_ui)
            
            start_stop_button.text = "Start Filter"
            start_stop_button.icon = ft.Icons.PLAY_ARROW
            start_stop_button.bgcolor = "#1B5E20"
            status_text.value = "Stopped"
            status_indicator.bgcolor = "red"
            is_filter_running = False
        
        page.update()

    start_stop_button.on_click = start_stop_filter

    control_tab = ft.Container(
        content=ft.Column([
            ft.Container(height=20),
            ft.Text("DNS Filter Control", size=24, weight=ft.FontWeight.BOLD),
            ft.Container(height=30),
            
            # Status Card
            ft.Container(
                content=ft.Column([
                    ft.Row([
                        ft.Icon(ft.Icons.INFO_OUTLINE, size=20),
                        ft.Text("Status", size=16, weight=ft.FontWeight.BOLD)
                    ]),
                    ft.Divider(),
                    ft.Row([
                        status_indicator,
                        status_text
                    ], spacing=10)
                ]),
                bgcolor="#2C2C2C",
                padding=20,
                border_radius=10,
                width=400
            ),
            
            ft.Container(height=20),
            start_stop_button,
            
            ft.Container(height=30),
            ft.Container(
                content=ft.Column([
                    ft.Icon(ft.Icons.WARNING_AMBER, color="orange", size=30),
                    ft.Text(
                        "Important: Administrator privileges required",
                        size=12,
                        color="orange",
                        text_align=ft.TextAlign.CENTER
                    ),
                    ft.Text(
                        "The filter modifies system DNS settings and firewall rules",
                        size=10,
                        color="grey",
                        text_align=ft.TextAlign.CENTER
                    )
                ], horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                bgcolor="#2C2C2C",
                padding=15,
                border_radius=10,
                width=400
            )
        ], horizontal_alignment=ft.CrossAxisAlignment.CENTER),
        padding=20,
        expand=True
    )

    # ==================== Tab 2: Live Logs ====================
    
    def clear_logs(e):
        log_viewer_container.controls.clear()
        add_log_to_ui("Logs cleared", update_page=True)

    logs_tab = ft.Container(
        content=ft.Column([
            ft.Row([
                ft.Text("Live DNS Logs", size=20, weight=ft.FontWeight.BOLD),
                ft.IconButton(
                    icon=ft.Icons.DELETE_SWEEP,
                    tooltip="Clear logs",
                    on_click=clear_logs
                )
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
            
            ft.Container(height=10),
            
            ft.Container(
                content=log_viewer_container,
                bgcolor="#1E1E1E",
                border_radius=10,
                padding=10,
                expand=True
            ),
            
            ft.Container(
                content=ft.Row([
                    ft.Row([
                        ft.Container(width=12, height=12, bgcolor="green", border_radius=6),
                        ft.Text("Allowed", size=10)
                    ], spacing=5),
                    ft.Row([
                        ft.Container(width=12, height=12, bgcolor="red", border_radius=6),
                        ft.Text("Blocked", size=10)
                    ], spacing=5),
                    ft.Row([
                        ft.Container(width=12, height=12, bgcolor="yellow", border_radius=6),
                        ft.Text("Cached", size=10)
                    ], spacing=5)
                ], spacing=20),
                padding=10
            )
        ], expand=True),
        padding=20,
        expand=True
    )

    # ==================== Tab 3: Domain Blocklist ====================
    
    domain_input = ft.TextField(
        label="Domain to block",
        hint_text="e.g., ads.google.com",
        expand=True
    )

    def add_domain(e):
        domain = domain_input.value.strip().lower()
        if domain:
            domains = load_dns_blocklist("manual_lists/domain_blocklist.txt")
            if domain not in domains:
                domains.add(domain)
                save_blocklist("manual_lists/domain_blocklist.txt", domains)
                add_log_to_ui(f"✓ Added '{domain}' to domain blocklist")
                update_blocklist_display()
            else:
                add_log_to_ui(f"⚠ '{domain}' already in blocklist")
            domain_input.value = ""
            page.update()

    domain_input.on_submit = add_domain

    domain_tab = ft.Container(
        content=ft.Column([
            ft.Text("Domain Blocklist Management", size=20, weight=ft.FontWeight.BOLD),
            ft.Container(height=10),
            
            ft.Row([
                domain_input,
                ft.IconButton(
                    icon=ft.Icons.ADD_CIRCLE,
                    tooltip="Add domain",
                    on_click=add_domain,
                    icon_color="green"
                )
            ]),
            
            ft.Container(height=20),
            
            ft.Row([
                ft.Text(f"Blocked Domains", size=16, weight=ft.FontWeight.BOLD),
                ft.IconButton(
                    icon=ft.Icons.REFRESH,
                    tooltip="Refresh list",
                    on_click=lambda e: update_blocklist_display()
                )
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
            
            ft.Container(
                content=domain_items_column,
                bgcolor="#1E1E1E",
                border_radius=10,
                padding=10,
                expand=True
            )
        ], expand=True),
        padding=20,
        expand=True
    )

    # ==================== Tab 4: IP Blocklist ====================
    
    ip_input = ft.TextField(
        label="IP Address to block",
        hint_text="e.g., 192.168.1.100",
        expand=True
    )

    def add_ip(e):
        ip = ip_input.value.strip()
        if ip:
            ips = load_ip_blocklist("manual_lists/ip_blocklist.txt")
            if ip not in ips:
                ips.add(ip)
                save_blocklist("manual_lists/ip_blocklist.txt", ips)
                add_log_to_ui(f"✓ Added '{ip}' to IP blocklist")
                update_blocklist_display()
            else:
                add_log_to_ui(f"⚠ '{ip}' already in blocklist")
            ip_input.value = ""
            page.update()

    ip_input.on_submit = add_ip

    ip_tab = ft.Container(
        content=ft.Column([
            ft.Text("IP Blocklist Management", size=20, weight=ft.FontWeight.BOLD),
            ft.Container(height=10),
            
            ft.Row([
                ip_input,
                ft.IconButton(
                    icon=ft.Icons.ADD_CIRCLE,
                    tooltip="Add IP",
                    on_click=add_ip,
                    icon_color="green"
                )
            ]),
            
            ft.Container(height=20),
            
            ft.Row([
                ft.Text(f"Blocked IPs", size=16, weight=ft.FontWeight.BOLD),
                ft.IconButton(
                    icon=ft.Icons.REFRESH,
                    tooltip="Refresh list",
                    on_click=lambda e: update_blocklist_display()
                )
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
            
            ft.Container(
                content=ip_items_column,
                bgcolor="#1E1E1E",
                border_radius=10,
                padding=10,
                expand=True
            )
        ], expand=True),
        padding=20,
        expand=True
    )

    # ==================== Tab 5: Whitelist ====================
    
    whitelist_input = ft.TextField(
        label="Domain to whitelist",
        hint_text="e.g., mycompany.com",
        expand=True
    )

    def add_whitelist(e):
        domain = whitelist_input.value.strip().lower()
        if domain:
            whitelisted = load_whitelist("manual_lists/domain_whitelist.txt")
            if domain not in whitelisted:
                whitelisted.add(domain)
                save_whitelist("manual_lists/domain_whitelist.txt", whitelisted)
                add_log_to_ui(f"✓ Added '{domain}' to whitelist")
                update_blocklist_display()
            else:
                add_log_to_ui(f"⚠ '{domain}' already in whitelist")
            whitelist_input.value = ""
            page.update()

    whitelist_input.on_submit = add_whitelist

    whitelist_tab = ft.Container(
        content=ft.Column([
            ft.Text("Domain Whitelist Management", size=20, weight=ft.FontWeight.BOLD),
            ft.Container(height=10),
            
            ft.Text(
                "Whitelisted domains are ALWAYS allowed, even if detected as malicious",
                size=11,
                color="orange",
                italic=True
            ),
            
            ft.Container(height=10),
            
            ft.Row([
                whitelist_input,
                ft.IconButton(
                    icon=ft.Icons.ADD_CIRCLE,
                    tooltip="Add domain",
                    on_click=add_whitelist,
                    icon_color="lightgreen"
                )
            ]),
            
            ft.Container(height=20),
            
            ft.Row([
                ft.Text(f"Whitelisted Domains", size=16, weight=ft.FontWeight.BOLD, color="lightgreen"),
                ft.IconButton(
                    icon=ft.Icons.REFRESH,
                    tooltip="Refresh list",
                    on_click=lambda e: update_blocklist_display()
                )
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
            
            ft.Container(
                content=whitelist_items_column,
                bgcolor="#1E1E1E",
                border_radius=10,
                padding=10,
                expand=True
            )
        ], expand=True),
        padding=20,
        expand=True
    )

    # ==================== Tab 6: Model Updates ====================
    
    update_dns_progress = ft.ProgressBar(visible=False)
    update_ip_progress = ft.ProgressBar(visible=False)
    
    update_dns_status = ft.Text("", size=12)
    update_ip_status = ft.Text("", size=12)
    
    # Training parameters
    epochs_input = ft.TextField(
        label="Epochs",
        value="5",
        width=100,
        keyboard_type=ft.KeyboardType.NUMBER,
        tooltip="Number of training epochs (default: 5)"
    )
    
    batch_size_input = ft.TextField(
        label="Batch Size",
        value="64",
        width=100,
        keyboard_type=ft.KeyboardType.NUMBER,
        tooltip="Training batch size (default: 64)"
    )
    
    learning_rate_input = ft.TextField(
        label="Learning Rate",
        value="0.0001",
        width=120,
        tooltip="Learning rate for optimizer (default: 0.0001)"
    )
    
    lora_rank_input = ft.TextField(
        label="LoRA Rank",
        value="8",
        width=100,
        keyboard_type=ft.KeyboardType.NUMBER,
        tooltip="LoRA rank parameter (default: 8)"
    )
    
    lora_alpha_input = ft.TextField(
        label="LoRA Alpha",
        value="16",
        width=100,
        keyboard_type=ft.KeyboardType.NUMBER,
        tooltip="LoRA alpha scaling (default: 16)"
    )

    def update_dns_model(e):
        update_dns_progress.visible = True
        update_dns_status.value = "Updating DNS model with new domains (LoRA)..."
        update_dns_status.color = "blue"
        page.update()
        
        def run_update():
            try:
                # Parse parameters
                epochs = int(epochs_input.value) if epochs_input.value else 5
                batch_size = int(batch_size_input.value) if batch_size_input.value else 64
                lr = float(learning_rate_input.value) if learning_rate_input.value else 0.0001
                lora_r = int(lora_rank_input.value) if lora_rank_input.value else 8
                lora_alpha = int(lora_alpha_input.value) if lora_alpha_input.value else 16
                
                add_log_to_ui(f"Starting DNS model update with params: epochs={epochs}, batch={batch_size}, lr={lr}")
                
                # Run incremental update with custom parameters
                result = incremental_update(
                    epochs=epochs,
                    batch_size=batch_size,
                    learning_rate=lr,
                    lora_r=lora_r,
                    lora_alpha=lora_alpha
                )
                
                if result is None or result[0] is None:
                    update_dns_status.value = "⚠ No new domains to train on"
                    update_dns_status.color = "orange"
                    add_log_to_ui("⚠ DNS model update skipped - no new domains")
                else:
                    update_dns_status.value = "✓ DNS model updated successfully (LoRA)"
                    update_dns_status.color = "green"
                    add_log_to_ui("✓ DNS model updated successfully with LoRA")
            except ValueError as ve:
                update_dns_status.value = f"✗ Invalid parameter: {str(ve)}"
                update_dns_status.color = "red"
                add_log_to_ui(f"✗ Invalid training parameter: {ve}")
            except Exception as ex:
                update_dns_status.value = f"✗ Update failed: {str(ex)}"
                update_dns_status.color = "red"
                add_log_to_ui(f"✗ DNS model update failed: {ex}")
            finally:
                update_dns_progress.visible = False
                page.update()
        
        threading.Thread(target=run_update, daemon=True).start()

    def update_ip_blocklist_data(e):
        update_ip_progress.visible = True
        update_ip_status.value = "Updating IP blocklist..."
        update_ip_status.color = "blue"
        page.update()
        
        def run_update():
            try:
                add_log_to_ui("Starting IP blocklist update...")
                ip_filter.update_blocklist()
                update_ip_status.value = "✓ IP blocklist updated successfully"
                update_ip_status.color = "green"
                add_log_to_ui("✓ IP blocklist updated successfully")
                update_blocklist_display()
            except Exception as ex:
                update_ip_status.value = f"✗ Update failed: {str(ex)}"
                update_ip_status.color = "red"
                add_log_to_ui(f"✗ IP blocklist update failed: {ex}")
            finally:
                update_ip_progress.visible = False
                page.update()
        
        threading.Thread(target=run_update, daemon=True).start()

    updates_tab = ft.Container(
        content=ft.Column([
            ft.Text("Model & Data Updates", size=20, weight=ft.FontWeight.BOLD),
            ft.Container(height=20),
            
            # DNS Model Update with Parameters
            ft.Container(
                content=ft.Column([
                    ft.Row([
                        ft.Icon(ft.Icons.MODEL_TRAINING, size=24),
                        ft.Text("DNS Model Incremental Update", size=16, weight=ft.FontWeight.BOLD)
                    ], spacing=10),
                    ft.Divider(),
                    ft.Text(
                        "Update ML model with NEW domains using LoRA (fast, efficient)",
                        size=12,
                        color="grey"
                    ),
                    ft.Text(
                        "Only trains on domains not seen before",
                        size=10,
                        color="grey",
                        italic=True
                    ),
                    ft.Container(height=15),
                    
                    # Training Parameters
                    ft.Text("Training Parameters:", size=13, weight=ft.FontWeight.BOLD),
                    ft.Container(height=5),
                    ft.Row([
                        epochs_input,
                        batch_size_input,
                        learning_rate_input
                    ], spacing=10),
                    ft.Container(height=5),
                    ft.Row([
                        lora_rank_input,
                        lora_alpha_input
                    ], spacing=10),
                    
                    ft.Container(height=15),
                    ft.ElevatedButton(
                        "Update DNS Model (LoRA)",
                        icon=ft.Icons.DOWNLOAD,
                        on_click=update_dns_model,
                        width=220
                    ),
                    update_dns_progress,
                    update_dns_status
                ]),
                bgcolor="#2C2C2C",
                padding=20,
                border_radius=10
            ),
            
            ft.Container(height=20),
            
            # IP Blocklist Update
            ft.Container(
                content=ft.Column([
                    ft.Row([
                        ft.Icon(ft.Icons.SECURITY, size=24),
                        ft.Text("IP Blocklist Update", size=16, weight=ft.FontWeight.BOLD)
                    ], spacing=10),
                    ft.Divider(),
                    ft.Text(
                        "Download latest malicious IP addresses from threat intelligence sources",
                        size=12,
                        color="grey"
                    ),
                    ft.Container(height=10),
                    ft.ElevatedButton(
                        "Update IP Blocklist",
                        icon=ft.Icons.DOWNLOAD,
                        on_click=update_ip_blocklist_data,
                        width=200
                    ),
                    update_ip_progress,
                    update_ip_status
                ]),
                bgcolor="#2C2C2C",
                padding=20,
                border_radius=10
            )
        ], scroll="auto"),
        padding=20,
        expand=True
    )

    # ==================== Tab 7: Settings ====================
    
    # DNS Filter method checkboxes - organized by category
    
    # Core Methods
    use_whitelist_check = ft.Checkbox(
        label="Use Whitelist",
        value=filter_config.get("use_whitelist", True),
        tooltip="Check against known legitimate domains (Google, Microsoft, etc.)"
    )
    
    use_manual_list_check = ft.Checkbox(
        label="Use Manual Blocklist",
        value=filter_config.get("use_manual_list", True),
        tooltip="Check domains against your manual blocklist"
    )
    
    # Heuristic Methods
    use_ip_check = ft.Checkbox(
        label="Block IP Addresses",
        value=filter_config.get("use_ip_check", True),
        tooltip="Block direct IP address queries (e.g., 192.168.1.1)"
    )
    
    use_punycode_check = ft.Checkbox(
        label="Block Punycode Domains",
        value=filter_config.get("use_punycode_check", True),
        tooltip="Block internationalized domains (often used in phishing)"
    )
    
    use_excessive_hyphens = ft.Checkbox(
        label="Block Excessive Hyphens",
        value=filter_config.get("use_excessive_hyphens", True),
        tooltip="Block domains with more than 3 hyphens (DGA indicator)"
    )
    
    use_long_label = ft.Checkbox(
        label="Block Long Labels",
        value=filter_config.get("use_long_label", True),
        tooltip="Block domains with labels longer than 30 characters"
    )
    
    use_hex_string = ft.Checkbox(
        label="Block Hex Strings",
        value=filter_config.get("use_hex_string", True),
        tooltip="Block domains with 32+ consecutive hex characters"
    )
    
    use_suspicious_tld = ft.Checkbox(
        label="Flag Suspicious TLDs",
        value=filter_config.get("use_suspicious_tld", True),
        tooltip="Lower ML threshold for .tk, .ml, .ga, .cf, .gq, etc."
    )
    
    use_dga_pattern = ft.Checkbox(
        label="Detect DGA Patterns",
        value=filter_config.get("use_dga_pattern", True),
        tooltip="Block domains with alternating consonant/vowel patterns"
    )
    
    # ML Method
    use_ml_model_check = ft.Checkbox(
        label="Use ML Model",
        value=filter_config.get("use_ml_model", True),
        tooltip="Use the trained machine learning model for classification"
    )
    
    # DNS Thresholds
    ml_threshold_slider = ft.Slider(
        min=0.0,
        max=1.0,
        divisions=100,
        value=filter_config.get("ml_threshold", 0.85),
        label="ML Threshold: {value}",
        width=300
    )
    
    ml_threshold_text = ft.Text(
        f"ML Threshold: {filter_config.get('ml_threshold', 0.85):.2f}",
        size=12,
        color="grey"
    )
    
    suspicious_tld_threshold_slider = ft.Slider(
        min=0.0,
        max=1.0,
        divisions=100,
        value=filter_config.get("suspicious_tld_threshold", 0.6),
        label="Suspicious TLD Threshold: {value}",
        width=300
    )
    
    suspicious_tld_threshold_text = ft.Text(
        f"Suspicious TLD Threshold: {filter_config.get('suspicious_tld_threshold', 0.6):.2f}",
        size=12,
        color="grey"
    )
    
    # IP Filter Methods
    ip_use_blocklist = ft.Checkbox(
        label="Use IP Blocklist",
        value=filter_config.get("ip_use_blocklist", True),
        tooltip="Check IPs against threat intelligence feeds"
    )
    
    ip_region_block = ft.Checkbox(
        label="Region Blocking",
        value=filter_config.get("ip_region_block", False),
        tooltip="Block IPs from specific countries"
    )
    
    ip_regex_check = ft.Checkbox(
        label="IP Pattern Check",
        value=filter_config.get("ip_regex_check", True),
        tooltip="Detect suspicious IP patterns"
    )
    
    ip_asn_block = ft.Checkbox(
        label="ASN Blocking",
        value=filter_config.get("ip_asn_block", False),
        tooltip="Block specific Autonomous System Numbers"
    )
    
    ip_rate_limit_check = ft.Checkbox(
        label="Rate Limiting",
        value=filter_config.get("ip_rate_limit_check", False),
        tooltip="Limit requests per IP address"
    )
    
    ip_block_tor = ft.Checkbox(
        label="Block Tor Exit Nodes",
        value=filter_config.get("ip_block_tor", False),
        tooltip="Block all Tor exit node IPs"
    )
    
    ip_block_vpn = ft.Checkbox(
        label="Block VPN IPs",
        value=filter_config.get("ip_block_vpn", False),
        tooltip="Block known VPN IP ranges"
    )
    
    ip_block_proxy = ft.Checkbox(
        label="Block Proxy Servers",
        value=filter_config.get("ip_block_proxy", False),
        tooltip="Block known proxy server IPs"
    )
    
    ip_block_datacenter = ft.Checkbox(
        label="Block Datacenter IPs",
        value=filter_config.get("ip_block_datacenter", False),
        tooltip="Block datacenter IP ranges (AWS, Azure, etc.)"
    )
    
    # IP Rate Limit Parameters
    ip_max_requests_input = ft.TextField(
        label="Max Requests",
        value=str(filter_config.get("ip_max_requests", 100)),
        width=120,
        keyboard_type=ft.KeyboardType.NUMBER,
        tooltip="Maximum requests allowed per IP"
    )
    
    ip_time_window_input = ft.TextField(
        label="Time Window (sec)",
        value=str(filter_config.get("ip_time_window", 60)),
        width=120,
        keyboard_type=ft.KeyboardType.NUMBER,
        tooltip="Time window for rate limiting in seconds"
    )
    
    def on_ml_threshold_change(e):
        ml_threshold_text.value = f"ML Threshold: {e.control.value:.2f}"
        page.update()
    
    def on_suspicious_tld_threshold_change(e):
        suspicious_tld_threshold_text.value = f"Suspicious TLD Threshold: {e.control.value:.2f}"
        page.update()
    
    ml_threshold_slider.on_change = on_ml_threshold_change
    suspicious_tld_threshold_slider.on_change = on_suspicious_tld_threshold_change
    
    settings_status = ft.Text("", size=12)
    
    def save_settings(e):
        # Update config with all methods
        try:
            new_config = {
                # DNS Core methods
                "use_whitelist": use_whitelist_check.value,
                "use_manual_list": use_manual_list_check.value,
                
                # DNS Heuristic methods
                "use_ip_check": use_ip_check.value,
                "use_punycode_check": use_punycode_check.value,
                "use_excessive_hyphens": use_excessive_hyphens.value,
                "use_long_label": use_long_label.value,
                "use_hex_string": use_hex_string.value,
                "use_suspicious_tld": use_suspicious_tld.value,
                "use_dga_pattern": use_dga_pattern.value,
                
                # DNS ML method
                "use_ml_model": use_ml_model_check.value,
                
                # DNS Thresholds
                "ml_threshold": ml_threshold_slider.value,
                "suspicious_tld_threshold": suspicious_tld_threshold_slider.value,
                
                # IP Filter methods
                "ip_use_blocklist": ip_use_blocklist.value,
                "ip_region_block": ip_region_block.value,
                "ip_regex_check": ip_regex_check.value,
                "ip_asn_block": ip_asn_block.value,
                "ip_rate_limit_check": ip_rate_limit_check.value,
                "ip_block_tor": ip_block_tor.value,
                "ip_block_vpn": ip_block_vpn.value,
                "ip_block_proxy": ip_block_proxy.value,
                "ip_block_datacenter": ip_block_datacenter.value,
                
                # IP Rate limiting
                "ip_max_requests": int(ip_max_requests_input.value) if ip_max_requests_input.value else 100,
                "ip_time_window": int(ip_time_window_input.value) if ip_time_window_input.value else 60
            }
            
            save_filter_config(new_config)
            
            settings_status.value = "✓ Settings saved successfully! Restart filter for changes to take effect."
            settings_status.color = "green"
            
            dns_enabled = sum(1 for k, v in new_config.items() if k.startswith('use_') and v)
            ip_enabled = sum(1 for k, v in new_config.items() if k.startswith('ip_') and isinstance(v, bool) and v)
            
            add_log_to_ui(f"✓ Filter settings updated")
            add_log_to_ui(f"  DNS methods: {dns_enabled} enabled")
            add_log_to_ui(f"  IP methods: {ip_enabled} enabled")
            
        except ValueError as ve:
            settings_status.value = f"✗ Invalid parameter: {str(ve)}"
            settings_status.color = "red"
            add_log_to_ui(f"✗ Settings save failed: Invalid parameter")
        
        page.update()
    
    settings_tab = ft.Container(
        content=ft.Column([
            ft.Text("Filter Settings", size=22, weight=ft.FontWeight.BOLD),
            ft.Container(height=15),
            
            # DNS FILTER SECTION
            ft.Text("━━━ DNS FILTERING ━━━", size=18, weight=ft.FontWeight.BOLD, color="cyan"),
            ft.Container(height=10),
            
            # DNS Core Methods Section
            ft.Container(
                content=ft.Column([
                    ft.Row([
                        ft.Icon(ft.Icons.SHIELD, size=22, color="blue"),
                        ft.Text("DNS Core Methods", size=15, weight=ft.FontWeight.BOLD)
                    ], spacing=10),
                    ft.Divider(height=1),
                    ft.Row([
                        use_whitelist_check,
                        use_manual_list_check,
                    ], spacing=20)
                ]),
                bgcolor="#2C2C2C",
                padding=12,
                border_radius=8,
                width=900
            ),
            
            ft.Container(height=10),
            
            # DNS Heuristic Methods Section
            ft.Container(
                content=ft.Column([
                    ft.Row([
                        ft.Icon(ft.Icons.PATTERN, size=22, color="orange"),
                        ft.Text("DNS Heuristic Methods", size=15, weight=ft.FontWeight.BOLD)
                    ], spacing=10),
                    ft.Divider(height=1),
                    ft.Row([
                        ft.Column([
                            use_ip_check,
                            use_punycode_check,
                            use_excessive_hyphens,
                        ], spacing=3),
                        ft.Column([
                            use_long_label,
                            use_hex_string,
                            use_dga_pattern,
                        ], spacing=3),
                        ft.Column([
                            use_suspicious_tld,
                        ], spacing=3),
                    ], spacing=40)
                ]),
                bgcolor="#2C2C2C",
                padding=12,
                border_radius=8,
                width=900
            ),
            
            ft.Container(height=10),
            
            # DNS ML Method Section
            ft.Container(
                content=ft.Column([
                    ft.Row([
                        ft.Icon(ft.Icons.PSYCHOLOGY, size=22, color="green"),
                        ft.Text("DNS Machine Learning", size=15, weight=ft.FontWeight.BOLD)
                    ], spacing=10),
                    ft.Divider(height=1),
                    use_ml_model_check,
                    
                    ft.Container(height=10),
                    
                    ft.Text("ML Model Threshold", size=13, weight=ft.FontWeight.BOLD),
                    ml_threshold_slider,
                    ml_threshold_text,
                    
                    ft.Container(height=10),
                    
                    ft.Text("Suspicious TLD Threshold", size=13, weight=ft.FontWeight.BOLD),
                    suspicious_tld_threshold_slider,
                    suspicious_tld_threshold_text,
                ]),
                bgcolor="#2C2C2C",
                padding=12,
                border_radius=8,
                width=900
            ),
            
            ft.Container(height=20),
            
            # IP FILTER SECTION
            ft.Text("━━━ IP FILTERING ━━━", size=18, weight=ft.FontWeight.BOLD, color="cyan"),
            ft.Container(height=10),
            
            # IP Core Methods
            ft.Container(
                content=ft.Column([
                    ft.Row([
                        ft.Icon(ft.Icons.SECURITY, size=22, color="red"),
                        ft.Text("IP Filter Methods", size=15, weight=ft.FontWeight.BOLD)
                    ], spacing=10),
                    ft.Divider(height=1),
                    ft.Row([
                        ft.Column([
                            ip_use_blocklist,
                            ip_region_block,
                            ip_regex_check,
                        ], spacing=3),
                        ft.Column([
                            ip_asn_block,
                            ip_rate_limit_check,
                            ip_block_tor,
                        ], spacing=3),
                        ft.Column([
                            ip_block_vpn,
                            ip_block_proxy,
                            ip_block_datacenter,
                        ], spacing=3),
                    ], spacing=40)
                ]),
                bgcolor="#2C2C2C",
                padding=12,
                border_radius=8,
                width=900
            ),
            
            ft.Container(height=10),
            
            # IP Rate Limit Parameters
            ft.Container(
                content=ft.Column([
                    ft.Row([
                        ft.Icon(ft.Icons.SPEED, size=22, color="purple"),
                        ft.Text("Rate Limiting Parameters", size=15, weight=ft.FontWeight.BOLD)
                    ], spacing=10),
                    ft.Divider(height=1),
                    ft.Text("(Only active when Rate Limiting is enabled)", size=10, color="grey", italic=True),
                    ft.Container(height=5),
                    ft.Row([
                        ip_max_requests_input,
                        ip_time_window_input,
                    ], spacing=20)
                ]),
                bgcolor="#2C2C2C",
                padding=12,
                border_radius=8,
                width=900
            ),
            
            ft.Container(height=20),
            
            # Save Button
            ft.ElevatedButton(
                "💾 Save All Settings",
                icon=ft.Icons.SAVE,
                on_click=save_settings,
                width=250,
                height=50,
                style=ft.ButtonStyle(
                    bgcolor=ft.Colors.GREEN_700,
                    color=ft.Colors.WHITE
                )
            ),
            settings_status,
            
            ft.Container(height=15),
            
            # Info Box
            ft.Container(
                content=ft.Column([
                    ft.Icon(ft.Icons.INFO_OUTLINE, color="blue", size=24),
                    ft.Text(
                        "Settings are saved immediately but require restarting the filter to take effect.",
                        size=11,
                        color="grey",
                        text_align=ft.TextAlign.CENTER
                    ),
                    ft.Text(
                        "DNS methods affect domain classification. IP methods affect resolved IP addresses.",
                        size=10,
                        color="grey",
                        text_align=ft.TextAlign.CENTER,
                        italic=True
                    )
                ], horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                bgcolor="#2C2C2C",
                padding=12,
                border_radius=8,
                width=900
            )
        ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, scroll="auto"),
        padding=20,
        expand=True
    )

    # ==================== Main Tab Navigation ====================
    
    tabs = ft.Tabs(
        selected_index=0,
        animation_duration=300,
        tabs=[
            ft.Tab(
                text="Control",
                icon=ft.Icons.SETTINGS,
                content=control_tab
            ),
            ft.Tab(
                text="Logs",
                icon=ft.Icons.LIST_ALT,
                content=logs_tab
            ),
            ft.Tab(
                text="Blocklist",
                icon=ft.Icons.BLOCK,
                content=domain_tab
            ),
            ft.Tab(
                text="IPs",
                icon=ft.Icons.ROUTER,
                content=ip_tab
            ),
            ft.Tab(
                text="Whitelist",
                icon=ft.Icons.CHECK_CIRCLE,
                content=whitelist_tab
            ),
            ft.Tab(
                text="Updates",
                icon=ft.Icons.SYSTEM_UPDATE,
                content=updates_tab
            ),
            ft.Tab(
                text="Settings",
                icon=ft.Icons.TUNE,
                content=settings_tab
            )
        ],
        expand=True
    )

    # Add everything to page
    page.add(tabs)
    
    # Initialize
    load_initial_logs()
    update_blocklist_display()

if __name__ == "__main__":
    ft.app(target=main)