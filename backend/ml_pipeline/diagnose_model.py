
import pandas as pd
import numpy as np
import ast
import json
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder

def train_and_diagnose():
    # Load
    df = pd.read_csv('backend/Training data/training_data.csv')
    if 'label' in df.columns:
        df.rename(columns={'label': 'Label'}, inplace=True)
    
    # Feature Engineering
    if 'total_l_fwd_packets' in df.columns:
        df['packet_size'] = df['total_l_fwd_packets']
    else:
        df['packet_size'] = df['packet_size'] # Assume exists in this CSV
        
    df['flow_duration'] = 0
    df['total_fwd_packets'] = 1
    df['total_l_fwd_packets'] = df['packet_size']
    
    # Protocol
    protocol_map = {'TCP': 6, 'UDP': 17, 'ICMP': 1, 'SCTP': 132}
    df['protocol_num'] = df['protocol'].map(protocol_map).fillna(0)
    
    # Metadata / Chaos
    def extract_chaos(x):
        try:
            s = str(x).replace('np.float64(', '').replace(')', '')
            d = ast.literal_eval(s)
            return float(d.get('chaos_factor', 0))
        except:
            return 0.0
    df['chaos_factor'] = df['metadata'].apply(extract_chaos)
    
    # Country (New Potential Feature)
    le = LabelEncoder()
    df['country_code'] = le.fit_transform(df['source_country'].astype(str))
    
    # Features to test
    feature_cols = [
        'dest_port', 'packet_size', 'protocol_num', 'chaos_factor', 'country_code'
    ]
    
    X = df[feature_cols]
    y = df['Label']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    clf = RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=42)
    clf.fit(X_train, y_train)
    
    y_pred = clf.predict(X_test)
    
    print("--- Classification Report ---")
    print(classification_report(y_test, y_pred))
    
    print("\n--- Feature Importance ---")
    for name, imp in zip(feature_cols, clf.feature_importances_):
        print(f"{name}: {imp:.4f}")

if __name__ == "__main__":
    train_and_diagnose()
