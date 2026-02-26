"""
Project: SentinAI NetGuard
Module: OCI Storage Manager
Description:
    Handles interactions with Oracle Cloud Infrastructure Object Storage.
    Used for archiving threat logs and diverse telemetry data to long-term cold storage
    to stay within Free Tier local storage limits.
"""

import os
import oci
import json
from datetime import datetime
from backend.core.config import config

class OCIStorageManager:
    def __init__(self):
        self.namespace = config.OCI_NAMESPACE
        self.bucket_name = config.OCI_BUCKET_NAME
        self.signer = None
        self.object_storage_client = None
        self.is_active = False

        self._initialize_client()

    def _initialize_client(self):
        """
        Initializes the OCI client using Instance Principals (when on VM) 
        or Default Config (when local).
        """
        try:
            # 1. Try Instance Principals (Preferred for OCI VMs)
            signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
            self.object_storage_client = oci.object_storage.ObjectStorageClient(
                config={}, 
                signer=signer
            )
            self.is_active = True
            print("[OCI Storage] Initialized using Instance Principals.")
        except Exception:
            try:
                # 2. Try Default Config (e.g. ~/.oci/config) for Local Dev
                self.object_storage_client = oci.object_storage.ObjectStorageClient(
                    oci.config.from_file(profile_name=config.OCI_CONFIG_PROFILE)
                )
                
                # Fetch Namespace if not provided
                if not self.namespace:
                    self.namespace = self.object_storage_client.get_namespace().data
                    
                self.is_active = True
                print(f"[OCI Storage] Initialized using Config File. Namespace: {self.namespace}")
            except Exception as e:
                print(f"[OCI Storage] Initialization Failed: {e}. Storage will be disabled.")
                self.is_active = False

    def upload_file(self, file_path: str, object_name: str = None) -> bool:
        """
        Uploads a file to the configured OCI bucket.
        """
        if not self.is_active:
            print("[OCI Storage] Client not active. Skipping upload.")
            return False

        if not object_name:
            object_name = os.path.basename(file_path)

        try:
            with open(file_path, 'rb') as f:
                self.object_storage_client.put_object(
                    self.namespace,
                    self.bucket_name,
                    object_name,
                    f
                )
            print(f"[OCI Storage] Successfully uploaded {object_name} to {self.bucket_name}")
            return True
        except Exception as e:
            print(f"[OCI Storage] Upload Failed: {e}")
            return False

    def archive_logs(self, log_data: list, prefix: str = "threat_logs"):
        """
        Archives a batch of log data as a JSON object.
        Naming convention: {prefix}_{timestamp}.json
        """
        if not self.is_active or not log_data:
            return False

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        object_name = f"{prefix}/{timestamp}.json"
        
        try:
            json_bytes = json.dumps(log_data, indent=2).encode('utf-8')
            
            self.object_storage_client.put_object(
                self.namespace,
                self.bucket_name,
                object_name,
                json_bytes
            )
            print(f"[OCI Storage] Archived {len(log_data)} records to {object_name}")
            return True
        except Exception as e:
            print(f"[OCI Storage] Archive Failed: {e}")
            return False

# Global Instance
oci_manager = OCIStorageManager()
