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
    JSON_DB_PATH = os.path.join(BASE_DIR, "threats.json")
    MODEL_PATH = os.path.join(BASE_DIR, "model_real.pkl")
    METRICS_PATH = os.path.join(BASE_DIR, "model_metrics.json")
    FEATURES_PATH = os.path.join(BASE_DIR, "feature_importance.json")
    
    # System Settings
    MAX_HISTORY_LIMIT = 100
    API_TITLE = "SentinAI NetGuard API"
    API_VERSION = "2.0.0"

config = AppConfig()
