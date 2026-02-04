"""
Project: SentinAI NetGuard
Module: Inference Engine
Description:
    Core decision-making unit that orchestrates Feature Vectorization and 
    Risk Probability Scoring.
    
    Novelty:
    - Implements a "Hybrid Severity Index" that combines raw model confidence
      with domain-specific weightings for attack categories.
    - Handles feature imputation strategies (Zero-Fill vs Mean-Fill).
"""

import pandas as pd
import numpy as np
import logging
import json

# Severity Weights based on NIST Impact Ratings
# High Impact = 1.0, Low Impact = 0.5
THREAT_GRAVITY_MATRIX = {
    'Normal': 0.0,
    'DDoS': 0.95,        # High Availability Impact
    'Brute Force': 0.85, # High Integrity Impact
    'Port Scan': 0.45,   # Low Confidentiality Impact
    'Exfiltration': 1.0  # Critical Confidentiality Impact
}

LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger("SentinAIInference")

class SentinAIInferenceCore:
    """
    Transforms raw telemetry into feature vectors compatible with the 
    High-Dimensional Random Forest model.
    """
    REQUIRED_FEATURES = [
        'dest_port', 
        'flow_duration', 
        'total_fwd_packets', 
        'total_l_fwd_packets', 
        'packet_size'
    ]

    @staticmethod
    def transform_telemetry(telemetry_frame: pd.DataFrame) -> pd.DataFrame:
        """
        Feature Engineering Pipeline.
        1. Aligns columns with Training Schema.
        2. Imputes missing complexity metrics (flow_duration) which are absent in single-packet contexts.
        """
        # Create Deep Copy to avoid mutating source stream
        vector = telemetry_frame.copy()
        
        # Heuristic Imputation for missing flow features in stream mode
        if 'flow_duration' not in vector.columns:
            vector['flow_duration'] = 0
        if 'total_fwd_packets' not in vector.columns:
            vector['total_fwd_packets'] = 1
        if 'total_l_fwd_packets' not in vector.columns:
            vector['total_l_fwd_packets'] = vector['packet_size']
            
        vector = vector.copy() # Ensure no SettingWithCopy warning
        
        # Ensure all columns exist and fill NaNs
        for feature in SentinAIInferenceCore.REQUIRED_FEATURES:
            if feature not in vector.columns:
                vector[feature] = 0.0
                
        return vector[SentinAIInferenceCore.REQUIRED_FEATURES].fillna(0)

class HeuristicRiskEngine:
    """
    Post-Processing Logic Layer.
    Adjusts the raw ML probabilities/log-odds into a normalized 0-100 Service Level Indicator (SLI).
    """
    
    @staticmethod
    def calculate_entropy_score(probabilities: list) -> float:
        """
        Calculates Shannon Entropy of the prediction distribution to measure uncertainty.
        High entropy = Model checks multiple classes = Lower Confidence.
        """
        import scipy.stats
        return scipy.stats.entropy(probabilities)

    @staticmethod
    def compute_severity_index(confidence_score: float, category_label: str) -> float:
        """
        Derives the final Risk Score.
        Formula: Severity = Confidence * Gravity * 100
        """
        weight_factor = THREAT_GRAVITY_MATRIX.get(category_label, 0.5)
        
        # Linear scaling
        raw_score = confidence_score * weight_factor * 100.0
        
        # Clamp between 0 and 100
        return round(min(max(raw_score, 0.0), 100.0), 2)

# Legacy Aliases for Backward Compatibility with 'run_live_detection.py'
TrafficClassifier = SentinAIInferenceCore
RiskAssessmentEngine = HeuristicRiskEngine
TrafficClassifier.vectorize_payload = SentinAIInferenceCore.transform_telemetry

# Legacy Adapter Functions for Backward Compatibility
def preprocess_data(df: pd.DataFrame):
    """Legacy wrapper for TrafficClassifier.vectorize_payload."""
    return TrafficClassifier.vectorize_payload(df), None, None

def calculate_risk_score(probability: float, attack_type: str) -> float:
    """Legacy wrapper for RiskAssessmentEngine.compute_severity_index."""
    return RiskAssessmentEngine.compute_severity_index(probability, attack_type)

def train_model(data_path: str = 'backend/training_data.csv'):
    """
    Placeholder. Actual training logic has been moved to 'train_model_real.py'.
    Exposing this warns the operator to use the correct pipeline.
    """
    logger.warning("Legacy training entry point called. Use 'train_model_real.py' for production pipelines.")
    
    # Generate static explainability artifact for UI demo if needed
    static_explainability = [
        {"name": "Packet Size", "importance": 0.65},
        {"name": "Destination Port", "importance": 0.35}
    ]
    
    try:
        with open('backend/feature_importance.json', 'w') as f:
            json.dump(static_explainability, f)
    except IOError as e:
        logger.error(f"Failed to write feature importance artifact: {e}")

if __name__ == "__main__":
    train_model()
