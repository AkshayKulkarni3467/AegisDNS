import flet as ft
import threading
import time
import dns_controller
from dns_utils import load_dns_blocklist, load_ip_blocklist, save_blocklist
from dns_model import incremental_update
from ip_model import IPFilterSystem

# Global state
is_filter_running = False
ip_filter = IPFilterSystem()

# UI Components that need global access
log_viewer_container = ft.Column(controls=[], scroll="auto", expand=True)
domain_items_column = ft.Column(controls=[], scroll="auto", expand=True)
ip_items_column = ft.Column(controls=[], scroll="auto", expand=True)

def main(page: ft.Page):
    global is_filter_running

    page.title = "DNS Filter Dashboard"
    page.window_width = 1000
    page.window_height = 700
    page.padding = 0
    page.theme_mode = ft.ThemeMode.DARK

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
        """Refresh the blocklist displays"""
        domain_items_column.controls.clear()
        ip_items_column.controls.clear()

        domains = sorted(list(load_dns_blocklist("domain_blocklist.txt")))
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

        ips = sorted(list(load_ip_blocklist("ip_blocklist.txt")))
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
        
        domain_items_column.update()
        ip_items_column.update()

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
            domains = load_dns_blocklist("domain_blocklist.txt")
            if domain not in domains:
                domains.add(domain)
                save_blocklist("domain_blocklist.txt", domains)
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
            ips = load_ip_blocklist("ip_blocklist.txt")
            if ip not in ips:
                ips.add(ip)
                save_blocklist("ip_blocklist.txt", ips)
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

    # ==================== Tab 5: Model Updates ====================
    
    update_dns_progress = ft.ProgressBar(visible=False)
    update_ip_progress = ft.ProgressBar(visible=False)
    
    update_dns_status = ft.Text("", size=12)
    update_ip_status = ft.Text("", size=12)

    def update_dns_model(e):
        update_dns_progress.visible = True
        update_dns_status.value = "Updating DNS model..."
        update_dns_status.color = "blue"
        page.update()
        
        def run_update():
            try:
                add_log_to_ui("Starting DNS model update...")
                incremental_update()
                update_dns_status.value = "✓ DNS model updated successfully"
                update_dns_status.color = "green"
                add_log_to_ui("✓ DNS model updated successfully")
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
            
            # DNS Model Update
            ft.Container(
                content=ft.Column([
                    ft.Row([
                        ft.Icon(ft.Icons.MODEL_TRAINING, size=24),
                        ft.Text("DNS Model Update", size=16, weight=ft.FontWeight.BOLD)
                    ], spacing=10),
                    ft.Divider(),
                    ft.Text(
                        "Update the machine learning model for DNS filtering",
                        size=12,
                        color="grey"
                    ),
                    ft.Container(height=10),
                    ft.ElevatedButton(
                        "Update DNS Model",
                        icon=ft.Icons.DOWNLOAD,
                        on_click=update_dns_model,
                        width=200
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
        ]),
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
                text="Domains",
                icon=ft.Icons.LANGUAGE,
                content=domain_tab
            ),
            ft.Tab(
                text="IPs",
                icon=ft.Icons.ROUTER,
                content=ip_tab
            ),
            ft.Tab(
                text="Updates",
                icon=ft.Icons.SYSTEM_UPDATE,
                content=updates_tab
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