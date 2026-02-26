"""
Script to launch the Live Packet Sniffer Service.
usage: python run_sniffer_service.py [interface]
"""
import os
import sys

# Ensure backend modules are in path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from backend.services.packet_sniffer import LivePacketSniffer

if __name__ == "__main__":
    print(">>> SentinAI Monitor Service Starting...")
    
    target_interface = "eth0"
    if len(sys.argv) > 1:
        target_interface = sys.argv[1]
        
    print(f"Target Interface: {target_interface}")
    
    try:
        sniffer = LivePacketSniffer(interface=target_interface)
        sniffer.start()
    except KeyboardInterrupt:
        print("\nService Stopped.")
    except Exception as e:
        print(f"Service Error: {e}")
