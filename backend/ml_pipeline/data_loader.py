"""
Project: SentinAI NetGuard
Module: Benchmark Data Adapter
Description:
    Provides compatibility for loading and normalizing standard academic 
    Intrusion Detection datasets (CIC-IDS-2017, NSL-KDD) for training.
    
    This component mitigates methodology risks by ensuring the model 
    can be validated against recognized benchmarks, not just synthetic data.
"""

import pandas as pd
import numpy as np
from typing import Dict, List, Optional
import os

class BenchmarkLoader:
    """
    Adapter pattern to normalize varying CSV schemas into the SentinAI Canonical Format.
    """
    
    # Internal Schema (SentinAI)
    CANONICAL_SCHEMA = {
        'dest_port': 'Destination Port',
        'flow_duration': 'Flow Duration',
        'total_fwd_packets': 'Total Fwd Packets',
        'total_l_fwd_packets': 'Total Length of Fwd Packets',
        'packet_size': 'packet_size', # Computed
        'label': 'Label'
    }

    # CIC-IDS-2017 Column Mapping
    CIC_IDS_MAP = {
        ' Destination Port': 'Destination Port',
        ' Flow Duration': 'Flow Duration',
        ' Total Fwd Packets': 'Total Fwd Packets', 
        'Total Length of Fwd Packets': 'Total Length of Fwd Packets',
        ' Label': 'Label'
    }
    
    # NSL-KDD Column Mapping (Partial)
    KDD_MAP = {
        'dst_bytes': 'Total Length of Fwd Packets',
        'duration': 'Flow Duration',
        'count': 'Total Fwd Packets', # Approx mapping
        'class': 'Label'
    }

    @classmethod
    def load_and_normalize(cls, file_path: str) -> pd.DataFrame:
        """
        Smart loader that detects dataset type and normalizes columns.
        """
        print(f"[BenchmarkLoader] Ingesting {os.path.basename(file_path)}...")
        
        try:
            # Load snippet first to inspect headers
            df_preview = pd.read_csv(file_path, nrows=1)
            columns = df_preview.columns.tolist()
            
            # Heuristic Detection
            if ' Destination Port' in columns or ' Flow Duration' in columns:
                return cls._process_cic_ids(file_path)
            elif 'dst_bytes' in columns:
                return cls._process_kdd(file_path)
            else:
                # Assume Internal/Synthetic Format
                print("[BenchmarkLoader] Detected Standard/Internal Schema.")
                return pd.read_csv(file_path)
                
        except Exception as e:
            print(f"[BenchmarkLoader] Error loading {file_path}: {e}")
            return pd.DataFrame()

    @classmethod
    def _process_cic_ids(cls, path: str) -> pd.DataFrame:
        print("[BenchmarkLoader] Detected Schema: CIC-IDS-2017")
        df = pd.read_csv(path)
        
        # Strip whitespace from headers (Common issue in CIC-IDS)
        df.columns = df.columns.str.strip()
        
        # Filter for relevant columns only to save memory
        # Note: CIC-IDS has 80+ columns
        relevant_cols = [
            'Destination Port', 'Flow Duration', 'Total Fwd Packets',
            'Total Length of Fwd Packets', 'Label'
        ]
        
        # Verify columns exist
        available_cols = [c for c in relevant_cols if c in df.columns]
        df = df[available_cols]
        
        return df

    @classmethod
    def _process_kdd(cls, path: str) -> pd.DataFrame:
        print("[BenchmarkLoader] Detected Schema: NSL-KDD")
        df = pd.read_csv(path)
        
        # Rename to Canonical
        df = df.rename(columns={
            'dst_bytes': 'Total Length of Fwd Packets',
            'duration': 'Flow Duration', 
            'count': 'Total Fwd Packets',
            'class': 'Label'
        })
        
        # Synthesis: KDD lacks 'Destination Port', assign generic 80
        df['Destination Port'] = 80
        
        return df
