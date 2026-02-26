"""
Core Configuration Module
-------------------------
Centralizes all environment variables and constant configurations for the application.
"""
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class AppConfig:
    """Application-wide configuration settings."""
    
    # Base Paths
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    # Database
    MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    DB_NAME = "threat_detection"
    COLLECTION_NAME = "threats"
    
    # File Paths (Legacy compatibility)
    JSON_DB_PATH = os.path.join(BASE_DIR, "data", "threats.json")
    MODEL_PATH = os.path.join(BASE_DIR, "model_real.pkl")
    METRICS_PATH = os.path.join(BASE_DIR, "model_metrics.json")
    FEATURES_PATH = os.path.join(BASE_DIR, "model_features.json")
    
    # System Settings
    MAX_HISTORY_LIMIT = 2000
    API_TITLE = "SentinAI NetGuard API"
    API_VERSION = "2.0.0"

    # Security & Environment
    DEBUG = os.getenv("DEBUG", "False").lower() == "true"
    SECRET_KEY = os.getenv("SECRET_KEY", "academic_project_secret_key_change_in_production") # Load from env

    # OCI Object Storage Configuration
    OCI_CONFIG_PROFILE = os.getenv("OCI_CONFIG_PROFILE", "DEFAULT")
    OCI_NAMESPACE = os.getenv("OCI_NAMESPACE", "")
    OCI_BUCKET_NAME = os.getenv("OCI_BUCKET_NAME", "sentinai-logs")
    OCI_REGION = os.getenv("OCI_REGION", "us-ashburn-1")
    
    # HIDS (Log Collector) Settings
    TARGET_SERVER_IP = os.getenv("TARGET_SERVER_IP", "192.168.1.103")
    TARGET_SSH_USER = os.getenv("TARGET_SSH_USER", "root")
    TARGET_SSH_PASSWORD = os.getenv("TARGET_SSH_PASSWORD", "password") # For demo only, prefer keys
    
    # Feature Flags
    ALLOW_EMERGENCY_ADMIN = os.getenv("ALLOW_EMERGENCY_ADMIN", "False").lower() == "true"
    
config = AppConfig()
