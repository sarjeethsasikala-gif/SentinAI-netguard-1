"""
Project: SentinAI NetGuard
Module: System Log Collector (HIDS)
Description:
    Connects to a remote server via SSH, tails the auth log,
    and detects suspicious system-level events (Failed Login, Sudo, etc.).
"""
import paramiko
import time
import re
import requests
import logging
from datetime import datetime
from backend.core.config import config

# Configure Logging
logging.basicConfig(level=logging.INFO, format='[LOG-COLLECTOR] %(message)s')
logger = logging.getLogger("LogCollector")

class LogCollector:
    def __init__(self):
        self.host = config.TARGET_SERVER_IP
        self.user = config.TARGET_SSH_USER
        self.password = config.TARGET_SSH_PASSWORD
        self.client = None
        self.channel = None

    def connect(self):
        """Establishes SSH connection."""
        try:
            logger.info(f"Connecting to {self.user}@{self.host}...")
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(self.host, username=self.user, password=self.password, timeout=10)
            logger.info("SSH Connection Established.")
            return True
        except Exception as e:
            logger.error(f"SSH Connection Failed: {e}")
            return False

    def process_line(self, line):
        """Analyzes a single log line."""
        line = line.strip()
        if not line: return

        alert = None
        
        # 1. Failed Password (Brute Force / Hydra)
        if "Failed password" in line:
            alert = {
                "label": "SSH Brute Force",
                "risk_score": 75,
                "details": line
            }
        
        # 2. Accepted Password (Compromise?)
        elif "Accepted password" in line:
            alert = {
                "label": "SSH Successful Login",
                "risk_score": 50, # Info/Warning
                "details": line
            }
            
        # 3. Sudo Usage (Privilege Escalation)
        elif "sudo:" in line and "COMMAND" in line:
            alert = {
                "label": "Privilege Escalation (Sudo)",
                "risk_score": 60,
                "details": line
            }

        # Dispatch Alert
        if alert:
            self.push_alert(alert)

    def push_alert(self, alert_data):
        """Constructs telemetry and pushes to API."""
        telemetry = {
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "source_ip": self.host,
            "destination_ip": "Local",
            "protocol": "SYSLOG",
            "packet_size": 0,
            "dest_port": 22,
            "label": alert_data["label"],
            "risk_score": alert_data["risk_score"],
            "confidence": 1.0, # Logs are facts, high confidence
            "metadata": {
                "log_line": alert_data["details"],
                "source": "HIDS"
            }
        }
        
        try:
            logger.warning(f"ALERT: {alert_data['label']}")
            requests.post("http://localhost:8000/api/internal/notify", json={
                "type": "THREAT_DETECTED",
                "data": telemetry
            }, timeout=0.5)
            
            # Note: We should also save to DB here, but API might handle it via a separate endpoint
            # For now, relying on the 'notify' hook if it persists, OR we persist directly:
            # db.save_event(telemetry) (Requires importing database)
            
        except Exception as e:
            logger.error(f"Failed to push alert: {e}")

    def start(self):
        """Main Loop: Tails the file."""
        if not self.connect():
            return

        stmt = "tail -f /var/log/auth.log"
        stdin, stdout, stderr = self.client.exec_command(stmt)
        
        logger.info(f"Tailing {stmt}...")
        
        try:
            for line in iter(stdout.readline, ""):
                self.process_line(line)
        except KeyboardInterrupt:
            logger.info("Stopping Collector.")
            self.client.close()
        except Exception as e:
            logger.error(f"Connection Lost: {e}")
            self.client.close()

if __name__ == "__main__":
    collector = LogCollector()
    collector.start()
