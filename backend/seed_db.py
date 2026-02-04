from pymongo import MongoClient
from pymongo.errors import ServerSelectionTimeoutError
import pandas as pd
import joblib
from log_generator import generate_log_entry
from detector import calculate_risk_score, preprocess_data, ASSET_CRITICALITY
import os
import json
from dotenv import load_dotenv

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = "threat_detection"
COLLECTION_NAME = "threats"
JSON_DB_PATH = "backend/threats.json"

def seed_database(num_records=100):
    print("Connecting to Database...")
    mongo_available = False
    try:
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=2000)
        client.server_info() # Trigger connection
        db = client[DB_NAME]
        collection = db[COLLECTION_NAME]
        mongo_available = True
    except ServerSelectionTimeoutError:
        print("MongoDB not found. Using local JSON file storage.")

    # Load model
    print("Loading model...")
    try:
        model = joblib.load('backend/model.pkl')
        encoder = joblib.load('backend/encoder.pkl')
    except Exception as e:
        print(f"Error loading model: {e}. Please train model first.")
        return

    print(f"Generating and analyzing {num_records} records...")
    threats_to_insert = []
    ip_alert_counts = {} # Temporal correlation
    
    for _ in range(num_records):
        log = generate_log_entry()
        
        df_single = pd.DataFrame([log])
        
        try:
            df_single['protocol_encoded'] = encoder.transform(df_single['protocol'])
        except ValueError:
            df_single['protocol_encoded'] = 0 
            
        df_single['asset_criticality'] = df_single['dest_ip'].map(ASSET_CRITICALITY).fillna(5)
        
        X = df_single[['packet_size', 'protocol_encoded', 'asset_criticality']]
        
        probs = model.predict_proba(X)[0]
        classes = model.classes_
        
        predicted_label = model.predict(X)[0]
        class_idx = list(classes).index(predicted_label)
        confidence = probs[class_idx]
        
        # New Risk Formula: Confidence * Severity Weight
        risk_score = calculate_risk_score(confidence, predicted_label)
        
        if predicted_label != 'Normal':
            # Temporal Analysis (Behavioral)
            # Escalate risk if same IP is attacking repeatedly
            src = log['source_ip']
            ip_alert_counts[src] = ip_alert_counts.get(src, 0) + 1
            
            if ip_alert_counts[src] > 5:
                # Repeated offender escalation
                risk_score = min(risk_score * 1.2, 100.0)
            
            threat_entry = {
                **log,
                'predicted_label': predicted_label,
                'attack_probability': float(confidence), # Fix: Use confidence of label
                'risk_score': risk_score,
                'timestamp_processed': pd.Timestamp.now().isoformat(),
                'escalation_flag': ip_alert_counts[src] > 5 # Marker for explanation
            }
            threats_to_insert.append(threat_entry)
            
    if threats_to_insert:
        if mongo_available:
            collection.insert_many(threats_to_insert)
            print(f"Inserted {len(threats_to_insert)} threats into MongoDB.")
        
        # Always save/update JSON for fallback or if primary
        existing_data = []
        if os.path.exists(JSON_DB_PATH):
            try:
                with open(JSON_DB_PATH, 'r') as f:
                    existing_data = json.load(f)
            except:
                pass
        
        existing_data.extend(threats_to_insert)
        with open(JSON_DB_PATH, 'w') as f:
            json.dump(existing_data, f, indent=2)
        print(f"Saved {len(threats_to_insert)} threats to {JSON_DB_PATH}")
        
    else:
        print("No threats generated to insert.")

if __name__ == "__main__":
    seed_database()
