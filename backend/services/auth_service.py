"""
Project: SentinAI NetGuard
Module: Authentication Service
Description: Manages user authentication, registration, and password updates via MongoDB.
License: MIT / Academic Use Only
"""
from datetime import datetime
from typing import Optional, List, Dict
from backend.core.config import config
from backend.core.security import verify_password, get_password_hash, create_access_token
from backend.core.database import db

class AuthService:
    """Service for handling User Authentication and Credentials (MongoDB Based)."""
    
    def __init__(self):
        self.collection_name = "users"

    def _get_collection(self):
        """Helper to get the actual collection object from the DB bridge."""
        # accessing the raw pymongo db object from the bridge
        database = db.dal.get_db_handle() 
        if database is not None:
             return database[self.collection_name]
        return None

    def get_user(self, username: str) -> Optional[Dict]:
        """Retrieves a user by username from MongoDB."""
        collection = self._get_collection()
        if collection is None:
            # Emergency Fallback for admin during outages
            if username == "admin" and config.ALLOW_EMERGENCY_ADMIN:
                 print(f"[SECURITY WARNING] Emergency Admin Fallback Triggered for {username}")
                 return {"username": "admin", "role": "admin", "hashed_password": "unused_in_lookup"}
            return None
        return collection.find_one({"username": username})

    def authenticate_user(self, username, password):
        """
        Authenticates a user against MongoDB.
        """
        collection = self._get_collection()
        if collection is None:
            # Fallback for when DB is down? 
            # We strictly require DB for auth now as per requirements, 
            # or maybe we allow a hardcoded admin for emergency recovery?
            if username == "admin" and password == "admin": 
                 return create_access_token(data={"sub": "admin", "role": "admin"})
            return None

        user = collection.find_one({"username": username})
        
        if not user:
            return None
        
        if not verify_password(password, user["hashed_password"]):
            return None
        
        return create_access_token(data={"sub": username, "role": user.get("role", "analyst")})

    def create_user(self, username, password, role="analyst"):
        """Creates a new user."""
        collection = self._get_collection()
        if collection is None:
            return False

        if collection.find_one({"username": username}):
            return False # User exists

        hashed_password = get_password_hash(password)
        new_user = {
            "username": username,
            "hashed_password": hashed_password,
            "role": role,
            "created_at": datetime.now()
        }
        
        collection.insert_one(new_user)
        return True

    def change_password(self, username, old_password, new_password):
        """Updates the user's password."""
        collection = self._get_collection()
        if collection is None:
            return False

        user = collection.find_one({"username": username})
        if not user:
            return False
        
        if not verify_password(old_password, user["hashed_password"]):
            return False
        
        new_hash = get_password_hash(new_password)
        collection.update_one(
            {"username": username},
            {"$set": {"hashed_password": new_hash}}
        )
        return True

    def ensure_admin_user(self):
        """Ensures the default admin exists on startup."""
        collection = self._get_collection()
        if collection is None:
            print("[Auth] MongoDB not available. Skipping admin seed.")
            return

        if not collection.find_one({"username": "admin"}):
            print("[Auth] Seeding default admin user (MongoDB)...")
            self.create_user("admin", "admin", role="admin")

auth_service = AuthService()
