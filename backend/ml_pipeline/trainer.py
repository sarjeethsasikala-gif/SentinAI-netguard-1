"""
Model Training Pipeline
-----------------------
A robust, class-based pipeline for training the Threat Detection Model.
Handles data loading, feature engineering, model training, and artifact persistence.
"""
import pandas as pd
import numpy as np
import pickle
import json
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, precision_recall_fscore_support
from sklearn.preprocessing import LabelEncoder
from backend.core.config import config

class CyberSecurityModelTrainer:
    """
    Manages the end-to-end training process for the anomaly detection model.
    """

    def __init__(self, data_path: str = None):
        # Default to a training data path relative to project root if not specified
        self.data_path = data_path or os.path.join(config.BASE_DIR, "Training data")
        self.model = None
        self.encoder = LabelEncoder()
        self.feature_columns = None
        
    def load_dataset(self) -> pd.DataFrame:
        """Loads and consolidates CSV data from the training directory."""
        print(f"[Trainer] Loading data from {self.data_path}...")
        dfs = []
        try:
            if not os.path.exists(self.data_path):
                 print(f"[Trainer] Warning: Data path {self.data_path} does not exist.")
                 return pd.DataFrame()

            for filename in os.listdir(self.data_path):
                if filename.endswith(".csv"):
                    file_path = os.path.join(self.data_path, filename)
                    # Use the new BenchmarkLoader for robust ingestion
                    from backend.ml_pipeline.data_loader import BenchmarkLoader
                    df = BenchmarkLoader.load_and_normalize(file_path)
                    
                    if not df.empty:
                        dfs.append(df)
            
            if not dfs:
                print("[Trainer] No csv files found.")
                return pd.DataFrame()

            full_df = pd.concat(dfs, ignore_index=True)
            print(f"[Trainer] Loaded {len(full_df)} records.")
            return full_df
        except Exception as e:
            print(f"[Trainer] Error loading data: {e}")
            return pd.DataFrame()

    def engineer_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Applies necessary transformations and feature engineering."""
        print("[Trainer] Engineering features...")
        
        # Clean column names
        df.columns = df.columns.str.strip()
        
        # Derived Feature: Packet Size calculation from Lengths
        # (Using safe access to avoid key errors if columns vary)
        if 'Total Length of Fwd Packets' in df.columns:
            df['packet_size'] = df['Total Length of Fwd Packets']
        elif 'Packet Length Mean' in df.columns:
            df['packet_size'] = df['Packet Length Mean']
        else:
            df['packet_size'] = 0

        # Handle Infinite/Null
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.dropna(inplace=True)
        
        return df

    def train(self, df: pd.DataFrame):
        """Trains the Random Forest model."""
        print("[Trainer] Starting training...")
        
        # Define Features & Target
        # Using the expanded feature set identified in previous optimization
        feature_cols = [
            'Destination Port', 'Flow Duration', 'Total Fwd Packets',
            'Total Length of Fwd Packets', 'packet_size' 
        ]
        # Attempt to add more columns if they exist in the dataset
        potential_features = [
             'Fwd Packet Length Max', 'Fwd Packet Length Mean', 'Flow Bytes/s', 
             'Flow Packets/s', 'Flow IAT Mean', 'Fwd Header Length', 
             'Min Packet Length', 'Max Packet Length', 'Packet Length Std', 
             'Average Packet Size', 'Active Mean', 'Idle Mean'
        ]
        
        for col in potential_features:
            if col in df.columns:
                feature_cols.append(col)
        
        self.feature_columns = feature_cols
        
        X = df[self.feature_columns]
        y = df['Label']

        # Split
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        # Train
        # Using balanced weights to handle rare attacks
        self.model = RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=42, n_jobs=-1)
        self.model.fit(X_train, y_train)
        
        print("[Trainer] Training complete.")
        
        # Evaluate internally
        self._evaluate(X_test, y_test)

    def _evaluate(self, X_test, y_test):
        """Internal evaluation helper."""
        y_pred = self.model.predict(X_test)
        acc = accuracy_score(y_test, y_pred)
        print(f"[Trainer] Validation Accuracy: {acc:.4f}")
        
        # Save detailed metrics
        precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='weighted')
        metrics = {
            "accuracy": acc,
            "precision": precision,
            "recall": recall,
            "f1_score": f1
        }
        with open(config.METRICS_PATH, "w") as f:
            json.dump(metrics, f, indent=4)

    def save_artifacts(self):
        """Persists model and metadata to disk."""
        if not self.model:
            print("[Trainer] No model to save.")
            return

        print(f"[Trainer] Saving artifacts to {config.BASE_DIR}...")
        
        # Save Model
        with open(config.MODEL_PATH, "wb") as f:
            pickle.dump(self.model, f)
            
        # Save Feature List (Important for Inference)
        with open(config.FEATURES_PATH, "w") as f:
            # Saving simple list for now, or full importance dict if available
            importances = self.model.feature_importances_
            feature_imp = [
                {"name": col, "value": float(imp)} 
                for col, imp in zip(self.feature_columns, importances)
            ]
            feature_imp.sort(key=lambda x: x['value'], reverse=True)
            json.dump(feature_imp[:15], f, indent=2) # Top 15 features

        print("[Trainer] Artifacts saved successfully.")

if __name__ == "__main__":
    trainer = CyberSecurityModelTrainer()
    data = trainer.load_dataset()
    if not data.empty:
        processed_data = trainer.engineer_features(data)
        trainer.train(processed_data)
        trainer.save_artifacts()
