"""
Project: SentinAI NetGuard
Module: Inference Engine
Description: Orchestrates the Machine Learning inference lifecycle.
             Responsibilities include model artifact loading, feature vectorization,
             and real-time anomaly prediction using Random Forest classifiers.
License: MIT / Academic Use Only
"""
import pickle
import pandas as pd
import numpy as np
import os
from datetime import datetime
from backend.core.config import config

class InferenceEngine:
    """
    Singleton Engine for handling ML predictions.
    
    Methodology:
    Utilizes a pre-trained Random Forest model to classify network flows.
    Raw telemetry is preprocessed into a feature vector matching the training schema (CIC-IDS-2017).
    Confidence scores are derived from class probabilities to compute a normalized 'Risk Score'.
    """
    
    _model = None
    _features = None

    @classmethod
    def load_model(cls):
        """Loads model artifacts from disk."""
        if cls._model is None:
            try:
                if os.path.exists(config.MODEL_PATH):
                    with open(config.MODEL_PATH, 'rb') as f:
                        cls._model = pickle.load(f)
                    print("[Inference] Model loaded successfully.")
                else:
                    print(f"[Inference] Warning: Model not found at {config.MODEL_PATH}")
            except Exception as e:
                print(f"[Inference] Error loading model: {e}")

    @staticmethod
    def preprocess_payload(packet_data: dict) -> pd.DataFrame:
        """
        Transforms raw packet dictionary into model-compatible DataFrame.
        Ensures all expected feature columns exist.
        """
        # Determine features (should ideally come from saved artifact)
        # Using hardcoded set based on known training script for stability
        expected_features = [
            'Destination Port', 'Flow Duration', 'Total Fwd Packets',
            'Total Backward Packets', 'Total Length of Fwd Packets',
            'Total Length of Bwd Packets', 'Fwd Packet Length Max',
            'Fwd Packet Length Min', 'Fwd Packet Length Mean',
            'Fwd Packet Length Std', 'Bwd Packet Length Max',
            'Bwd Packet Length Min', 'Bwd Packet Length Mean',
            'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s',
            'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
            'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max',
            'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std',
            'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags',
            'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length',
            'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
            'Min Packet Length', 'Max Packet Length', 'Packet Length Mean',
            'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count',
            'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count',
            'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count',
            'ECE Flag Count', 'Down/Up Ratio', 'Average Packet Size',
            'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
            'Fwd Header Length.1', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk',
            'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk',
            'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', 'Subflow Fwd Bytes',
            'Subflow Bwd Packets', 'Subflow Bwd Bytes', 'Init_Win_bytes_forward',
            'Init_Win_bytes_backward', 'act_data_pkt_fwd',
            'min_seg_size_forward', 'Active Mean', 'Active Std', 'Active Max',
            'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
        ]

        # Init DF with zeros
        df = pd.DataFrame(0, index=[0], columns=expected_features)

        # Map known inputs
        df['Destination Port'] = packet_data.get('dest_port', 80)
        df['Total Length of Fwd Packets'] = packet_data.get('packet_size', 0)
        
        # Synthetic estimation for missing flow features
        # (This is a simplified mapping logic for real-time simulation)
        df['Flow Duration'] = np.random.randint(100, 10000)
        df['Total Fwd Packets'] = np.random.randint(1, 20)
        
        return df

    @classmethod
    def predict(cls, packet_data: dict) -> dict:
        """
        Runs inference on a single packet.
        Returns dictionary with prediction and confidence.
        """
        if cls._model is None:
            cls.load_model()
            
        if cls._model is None:
            return {"label": "Unknown", "confidence": 0.0, "risk_score": 0}

        try:
            input_df = cls.preprocess_payload(packet_data)
            prediction = cls._model.predict(input_df)[0]
            probs = cls._model.predict_proba(input_df)[0]
            confidence = max(probs)
            
            # Risk Scoring
            risk_map = {
                'DDoS': 95, 'Port Scan': 70, 'Bot': 85,
                'Infiltration': 90, 'Web Attack': 75,
                'Brute Force': 80, 'BENIGN': 10
            }
            
            # Adjust risk based on confidence
            base_risk = risk_map.get(prediction, 50)
            if prediction == 'BENIGN':
                risk_score = 10
            else:
                risk_score = min(100, int(base_risk * confidence + 10))

            return {
                "label": prediction,
                "confidence": float(confidence),
                "risk_score": risk_score
            }
        except Exception as e:
            print(f"[Inference] Prediction Error: {e}")
            return {"label": "Error", "confidence": 0.0, "risk_score": 0}

# Initialize on import
InferenceEngine.load_model()
