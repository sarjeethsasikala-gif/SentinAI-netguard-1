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
from backend.engine.inference import InferenceEngine

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

            # 2. Construct Telemetry Object
            telemetry = {
                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "source_country": "UNK", 
                "protocol": protocol,
                "packet_size": packet_len,
                "dest_port": dest_port,
            }

            # 3. Detect Threat using ML Engine
            prediction = InferenceEngine.predict(telemetry)
            
            label = prediction["label"]
            risk_score = prediction["risk_score"]
            confidence = prediction["confidence"]

            telemetry['label'] = label
            telemetry['risk_score'] = risk_score
            telemetry['confidence'] = confidence
            telemetry['metadata'] = {"live_capture": True}

            # 4. Save to Database (if Threat or Sampling)
            # Log all threats, but sample normal traffic to save DB space
            if label != "BENIGN" and label != "Normal": 
                logger.warning(f"THREAT DETECTED: {src_ip} -> {dst_ip} [{label}] Risk: {risk_score}")
                db.save_event(telemetry)
                
                # 5. Real-Time Broadcast
                try:
                    requests.post("http://127.0.0.1:8000/api/internal/notify", json={
                        "type": "THREAT_DETECTED",
                        "data": telemetry
                    }, timeout=0.5)
                except Exception:
                    pass # Fail silently for broadcast
            
            elif self.packet_count % 100 == 0:
                # Heartbeat log for normal traffic
                logger.info(f"Monitor Active: Processed {self.packet_count} packets...")

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
