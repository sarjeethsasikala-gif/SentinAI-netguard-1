"""
Project: SentinAI NetGuard
Module: Standalone Log Generator (VM1 Service)
Description:
    Runs independently on a dedicated VM (or container).
    Generates synthetic network telemetry and pushes it to the Central Detector API.
    
    Features:
    - Stateless execution
    - HTTP Push to Detector
    - Retry logic for network resilience
"""
import os
import time
import requests
import json
import logging
from backend.log_generator import _synthesizer

# Configuration
# Can be set via Env Var (e.g. for Docker)
DETECTOR_API_URL = os.getenv("DETECTOR_API_URL", "http://localhost:8000/api/telemetry")
PUSH_INTERVAL = float(os.getenv("PUSH_INTERVAL", "2.0")) # Seconds between bursts
BURST_SIZE = int(os.getenv("BURST_SIZE", "50"))

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - [GeneratorVM] - %(message)s')
logger = logging.getLogger("LogGenerator")

def generate_and_push():
    """Core Loop"""
    logger.info(f"Starting Telemetry Stream to {DETECTOR_API_URL}")
    
    while True:
        try:
            # 1. Generate Batch
            # Using the existing sanitizer logic
            df = _synthesizer.generate_batch(BURST_SIZE)
            
            # Convert to JSON-serializable list
            payload = df.to_dict(orient='records')
            
            # 2. Push to API
            response = requests.post(
                DETECTOR_API_URL, 
                json=payload,
                timeout=5
            )
            
            if response.status_code == 200:
                logger.info(f"Pushed {len(payload)} events. Status: OK")
            else:
                logger.warning(f"Push Failed: {response.status_code} - {response.text}")
                
        except requests.exceptions.ConnectionError:
            logger.error(f"Connection Refused: {DETECTOR_API_URL} unreachable. Retrying...")
            time.sleep(5) # Backoff
        except Exception as e:
            logger.error(f"Generator Error: {e}")
            
        time.sleep(PUSH_INTERVAL)

if __name__ == "__main__":
    generate_and_push()
