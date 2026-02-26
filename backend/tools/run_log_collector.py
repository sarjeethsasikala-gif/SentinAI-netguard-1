"""
Project: SentinAI NetGuard
Module: Log Collector Launcher
Description:
    Utility script to safely launch the SSH Log Collector service
    with the correct Python environment context.
"""
import os
import sys

# Ensure backend modules are in path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from backend.services.log_collector import LogCollector

if __name__ == "__main__":
    print(">>> SentinAI SSH Log Collector Starting...")
    print(f"Target: {os.getenv('TARGET_SERVER_IP', 'Default')}")
    
    try:
        collector = LogCollector()
        collector.start()
    except KeyboardInterrupt:
        print("\nService Stopped.")
    except Exception as e:
        print(f"Service Error: {e}")
