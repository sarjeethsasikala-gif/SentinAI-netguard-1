"""
Project: SentinAI NetGuard
Module: Active Packet Sniffer
Description:
    Captures live network traffic using Scapy, extracts features,
    and feeds them into the ML Detector for real-time classification.
"""

import sys
import os
import time
import requests
import logging
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP
from backend.core.database import db
from backend.services.threat_service import threat_service

# Configure Logging
logging.basicConfig(level=logging.INFO, format='[SNIFFER] %(message)s')
logger = logging.getLogger("PacketSniffer")

# Mock "Detector" integration for now (Connecting to existing logic)
# Ideally, we would import the ML model here
# from backend.ml_pipeline.run_live_detection import predict_packet

class LivePacketSniffer:
    def __init__(self, interface="eth0"):
        self.interface = interface
        self.packet_count = 0

    def process_packet(self, packet):
        """Callback function for every captured packet."""
        try:
            if IP not in packet:
                return

            self.packet_count += 1
            
            # 1. Extract Features
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            packet_len = len(packet)
            protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "ICMP" if ICMP in packet else "OTHER"
            
            # Filter loopback to avoid noise
            if src_ip == "127.0.0.1": 
                return

            dest_port = 0
            if TCP in packet: dest_port = packet[TCP].dport
            elif UDP in packet: dest_port = packet[UDP].dport

            # 2. Construct Telemetry Object (Matching log_generator schema)
            telemetry = {
                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "source_country": "UNK", # Real deployment would use GeoIP
                "protocol": protocol,
                "packet_size": packet_len,
                "dest_port": dest_port,
                "label": "Analyzing..." # To be filled by ML
            }

            # 3. Detect Threat (Simplistic Heuristic for Demo)
            # In full version, call: label, risk = ml_model.predict(telemetry)
            label = "Normal"
            risk_score = 10
            
            # Simulated Detection Logic based on Port/Rate
            if dest_port in [22, 3389] and self.packet_count > 10:
                label = "Brute Force"
                risk_score = 75
            elif packet_len > 1000 and protocol == "ICMP":
                label = "DDoS"
                risk_score = 90
            elif self.packet_count > 100: # Fast rate
                label = "DDoS"
                risk_score = 85

            telemetry['label'] = label
            telemetry['risk_score'] = risk_score
            telemetry['metadata'] = {"live_capture": True}

            # 4. Save to Database (if Threat)
            # Only save interesting events to avoid flooding DB
            if label != "Normal" or (self.packet_count % 50 == 0):
                logger.info(f"Captured: {src_ip} -> {dst_ip} [{protocol}] : {label}")
                db.save_event(telemetry)

                # 5. Real-Time Broadcast (WhatsApp-style Push)
                try:
                    # Notify the API Gateway to push this to the UI
                    requests.post("http://localhost:8000/api/internal/notify", json={
                        "type": "THREAT_DETECTED",
                        "data": telemetry
                    }, timeout=0.5)
                except Exception as ex:
                    # Non-blocking: If API is down, just log it. Sniffer must survive.
                    logger.debug(f"Broadcast failed: {ex}")

        except Exception as e:
            logger.error(f"Error processing packet: {e}")

    def start(self):
        logger.info(f"Starting Sniffer on interface: {self.interface}...")
        logger.info("Press CTRL+C to stop.")
        
        # Determine interface automatically if 'any' or windows
        if sys.platform == "win32":
            iface = None # Scapy picks default on Windows
        else:
            iface = self.interface

        try:
            sniff(iface=iface, prn=self.process_packet, store=0)
        except KeyboardInterrupt:
            logger.info("Stopping Sniffer.")
        except Exception as e:
            logger.error(f"Sniffer Failed: {e}")

if __name__ == "__main__":
    # Default to eth0 for Linux (Server), or let Scapy decide
    target_iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
    sniffer = LivePacketSniffer(interface=target_iface)
    sniffer.start()
