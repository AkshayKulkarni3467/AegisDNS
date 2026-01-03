import pydivert
import time

def start_dns_divert():
    """
    Redirect DNS traffic from port 53 to port 6667.
    Includes error handling and automatic recovery.
    """
    FILTER = "udp.DstPort == 53 and ip.DstAddr == 127.0.0.1"
    
    max_retries = 5
    retry_delay = 2
    
    for attempt in range(max_retries):
        try:
            print(f"Starting DNS traffic redirection (attempt {attempt + 1}/{max_retries})...")
            
            with pydivert.WinDivert(FILTER) as w:
                print("Successfully started DNS traffic redirection: 127.0.0.1:53 -> 127.0.0.1:6667")
                
                consecutive_errors = 0
                max_consecutive_errors = 10
                
                for packet in w:
                    try:
                        packet.dst_port = 6667
                        w.send(packet)
                        consecutive_errors = 0  
                        
                    except Exception as send_error:
                        consecutive_errors += 1
                        print(f"Error redirecting packet: {send_error}")
                        
                        if consecutive_errors >= max_consecutive_errors:
                            print(f"Too many consecutive packet errors ({consecutive_errors}), restarting divert...")
                            break  
                        
                        time.sleep(0.01)
                        continue
                        
        except PermissionError:
            print("ERROR: WinDivert requires Administrator privileges!")
            print("Please run this script as Administrator.")
            return
            
        except Exception as e:
            print(f"Error in WinDivert (attempt {attempt + 1}/{max_retries}): {e}")
            
            if attempt < max_retries - 1:
                print(f"Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
                retry_delay *= 2  
            else:
                print("Failed to start DNS diversion after maximum retries.")
                return
    
    print("DNS diversion stopped.")