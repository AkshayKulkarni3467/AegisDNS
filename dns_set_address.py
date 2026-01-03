import subprocess
import json

def run_powershell_command(command_str):
    print(f"Executing: {command_str}")
    try:
        subprocess.run(['powershell.exe', '-Command', command_str], check=True, capture_output=True, text=True)
        print("Command executed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error: Command failed with exit code {e.returncode}")
        print("Stderr:", e.stderr)
        raise
    


def reset_dns_on_exit():
    print("\nProgram is exiting. Resetting DNS settings...")
    try:
        # Get all network adapters that are 'Up'
        output = subprocess.check_output(
            ['powershell', '-Command',
             'Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Select-Object -ExpandProperty Name | ConvertTo-Json'],
            text=True
        )
        interfaces = json.loads(output)

        # Normalize to list
        if not isinstance(interfaces, list):
            interfaces = [interfaces]

        for iface in interfaces:
            cmd = f'Set-DnsClientServerAddress -InterfaceAlias "{iface}" -ResetServerAddresses'
            print(f"Resetting DNS for: {iface}")
            subprocess.run(['powershell', '-Command', cmd], check=True, capture_output=True, text=True)

        print("✅ All DNS settings have been reset to default.")

    except Exception as e:
        print(f"⚠️ Failed to reset DNS automatically. You may need to do this manually. Error: {e}")
