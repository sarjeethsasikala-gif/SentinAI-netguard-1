"""
Project: AegisCore
Module: Network Sentinel (Live Monitor)
Description:
    The persistent surveillance loop that orchestrates the flow of synthetic
    telemetry through the inference engine and persists actionable intelligence
    to the data layer.

    Optimization:
    - Loads Model ONCE at startup (Singleton).
    - Batches DB writes for efficiency.
"""

import pandas as pd
import joblib
import time
import uuid
import os
import json
import logging
from datetime import datetime
from dotenv import load_dotenv

# Internal Modules
try:
    from backend.detector import TrafficClassifier, RiskAssessmentEngine, calculate_risk_score
    from backend.services.oci_storage import oci_manager # New OCI Integration
except ImportError:
    # Fallback for direct execution where 'backend' package isn't resolved
    from backend.detector import TrafficClassifier, RiskAssessmentEngine, calculate_risk_score
    # Mock for local run without package structure
    class MockOCI:
        def archive_logs(self, *args, **kwargs): pass
    oci_manager = MockOCI()

load_dotenv()

# Logger Configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - [Sentinel] - %(message)s')
logger = logging.getLogger("NetworkSentinel")

class SentinelConfig:
    # Base Directory Resolution (Robust against CWD)
    _BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    
    # Storage for disconnected environments
    LOCAL_STORAGE_PATH = os.path.join(os.path.dirname(_BASE_DIR), "data", "threats.json")
    MODEL_PATH = os.path.join(_BASE_DIR, "model_real.pkl")

class IntelligencePersistence:
    """Handles data storage (Local JSON Only)."""
    
    def __init__(self):
        pass # No DB connection needed
        
    def persist_batch(self, events: list):
        if not events:
            return

        # Local Fallback (for UI polling compatibility)
        self._update_local_cache(events)

    def _update_local_cache(self, new_events: list):
        """Maintains the rolling window of recent events."""
        current_cache = []
        if os.path.exists(SentinelConfig.LOCAL_STORAGE_PATH):
            try:
                with open(SentinelConfig.LOCAL_STORAGE_PATH, 'r') as f:
                    current_cache = json.load(f)
            except Exception:
                pass # Corrupt or empty file

        # Merge Strategy: Newest First
        # Prepend new events
        updated_cache = new_events + current_cache
        # Retention Policy: Keep last 200 items to prevent IO starvation
        updated_cache = updated_cache[:200]

        # Serialization Fix: Ensure ObjectId is converted to string
        def json_serial(obj):
            """JSON serializer for objects not serializable by default json code"""
            from bson import ObjectId
            if isinstance(obj, ObjectId):
                return str(obj)
            return str(obj)

        try:
            with open(SentinelConfig.LOCAL_STORAGE_PATH, 'w') as f:
                json.dump(updated_cache, f, indent=2, default=json_serial)
        except Exception as e:
            logger.error(f"Local Cache Update Failed: {e}")


class NetworkSentinel:
    """
    The Active Monitoring Agent.
    """
    def __init__(self):
        self.model = self._load_inference_model()
        self.persistence = IntelligencePersistence()
        self.offender_history = {} # In-memory state for temporal correlation
        self.batch_counter = 0 # Track bursts for archival
        self.archival_buffer = [] # Store incidents for OCI upload

    def _load_inference_model(self):
        """Loads the predictive model into memory."""
        try:
            logger.info(f"Loading Inference Model from {SentinelConfig.MODEL_PATH}...")
            # P0 Optimization: Load once, reuse forever
            return joblib.load(SentinelConfig.MODEL_PATH)
        except Exception as e:
            logger.critical(f"FATAL: Model Loading Failed - {e}")
            return None

    def process_telemetry_batch(self, telemetry_batch: list):
        """
        Ingests and analyzes a batch of telemetry records pushed from VM1.
        """
        if self.model is None or not telemetry_batch:
            return

        logger.info(f"Processing batch of {len(telemetry_batch)} records...")
        
        detected_incidents = []
        
        for telemetry in telemetry_batch:
            # 1. Vectorize for Model
            # Ensure keys match what Generator sends
            raw_frame = pd.DataFrame([{
                'dest_port': telemetry.get('dest_port', 0),
                'packet_size': telemetry.get('packet_size', 0),
                'protocol': telemetry.get('protocol', 'TCP'),
                'source_country': telemetry.get('source_country', 'Unknown'),
                'metadata': telemetry.get('metadata', {})
            }])
            
            # Use Domain Classifier to ensure Feature Completeness
            input_vector = TrafficClassifier.vectorize_payload(raw_frame)

            try:
                # 2. Inference
                probs = self.model.predict_proba(input_vector)[0]
                classes = self.model.classes_
                predicted_label = self.model.predict(input_vector)[0]
                
                # Get confidence score for the predicted class
                class_index = list(classes).index(predicted_label)
                confidence = probs[class_index]

                # 3. Assessment
                severity_index = RiskAssessmentEngine.compute_severity_index(confidence, predicted_label)

                if predicted_label != 'Normal':
                    # 4. Temporal Analysis (Repeat Offender Check)
                    src_ip = telemetry.get('source_ip', '0.0.0.0')
                    self.offender_history[src_ip] = self.offender_history.get(src_ip, 0) + 1
                    
                    escalation_flag = False
                    if self.offender_history[src_ip] > 1:
                        # Escalate severity for persistent threats
                        severity_index = min(severity_index * 1.2, 100.0)
                        escalation_flag = True
                        logger.warning(f"ESCALATION: Repeat offender {src_ip} detected! Risk bumped to {severity_index}")

                    logger.info(f"THREAT DETECTED: {predicted_label} from {src_ip} (Severity: {severity_index})")

                    # 5. Incident Creation
                    incident_record = {
                        "id": str(uuid.uuid4()),
                        "timestamp": telemetry.get('timestamp', datetime.now().isoformat()),
                        "source_ip": telemetry.get('source_ip'),
                        "destination_ip": telemetry.get('destination_ip'),
                        "destination_port": telemetry.get('dest_port'),
                        "protocol": telemetry.get('protocol'),
                        "packet_size": telemetry.get('packet_size'),
                        "predicted_label": predicted_label,
                        "confidence": float(confidence),
                        "risk_score": severity_index, # API Expects 'risk_score'
                        "status": "Active",
                        "escalation_flag": escalation_flag
                    }
                    detected_incidents.append(incident_record)
            
            except Exception as e:
                logger.error(f"Inference Cycle Error: {e}")

        # 6. Batch Persistence
        if detected_incidents:
            self.persistence.persist_batch(detected_incidents)
            self.archival_buffer.extend(detected_incidents)
            logger.info(f"Registered {len(detected_incidents)} new security incidents.")
        else:
            logger.info("Batch analysis complete. No threats detected.")

        # 8. OCI Archival Check (Every 10 bursts)
        self.batch_counter += 1
        if self.batch_counter >= 10:
            if self.archival_buffer:
                logger.info(f"[OCI] Triggering archival for {len(self.archival_buffer)} records...")
                success = oci_manager.archive_logs(self.archival_buffer)
                if success:
                    self.archival_buffer = [] # Clear buffer on success
                    logger.info("[OCI] Archival successful. Buffer cleared.")
                else:
                    logger.warning("[OCI] Archival failed. Keeping data in buffer.")
            
            self.batch_counter = 0


# Singleton Instance to be imported by API
sentinel_service = NetworkSentinel()

if __name__ == "__main__":
    logger.info("Starting Sentinel in Standalone Mode...")
    # In standalone, we might want to listen to a queue or just wait
    # For now, we do nothing as it's push-based from API
    while True:
        time.sleep(1)
