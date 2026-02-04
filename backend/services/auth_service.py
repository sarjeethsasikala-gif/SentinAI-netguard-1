"""
Project: SentinAI NetGuard
Module: Authentication Service
Description: Manages user authentication, registration, and password updates via Local JSON storage.
License: MIT / Academic Use Only
"""
from datetime import datetime
import json
import os
from typing import Optional, List, Dict
from backend.core.config import config
from backend.core.security import verify_password, get_password_hash, create_access_token

class AuthService:
    """Service for handling User Authentication and Credentials (JSON Based)."""
    
    def __init__(self):
        # Resolve path relative to this file or config
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.users_file = os.path.join(base_dir, "users.json")
        self._ensure_users_file()

    def _ensure_users_file(self):
        """Creates the users file if it doesn't exist."""
        if not os.path.exists(self.users_file):
            with open(self.users_file, 'w') as f:
                json.dump([], f)

    def _load_users(self) -> List[Dict]:
        """Reads users from JSON."""
        try:
            with open(self.users_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"[Auth] Failed to load users: {e}")
            return []

    def _save_users(self, users: List[Dict]):
        """Writes users to JSON."""
        try:
            with open(self.users_file, 'w') as f:
                json.dump(users, f, indent=2, default=str)
        except Exception as e:
            print(f"[Auth] Failed to save users: {e}")

    def authenticate_user(self, username, password):
        """
        Authenticates a user against the local file.
        Returns access token if successful, None otherwise.
        """
        users = self._load_users()
        user = next((u for u in users if u["username"] == username), None)
        
        if not user:
            # First run fallback if file empty/corrupt but admin requested
            if username == "admin" and password == "admin":
                 # Auto-create admin if missing in a fresh switch to local
                 self.create_user("admin", "admin", role="admin")
                 return create_access_token(data={"sub": "admin", "role": "admin"})
            return None
        
        if not verify_password(password, user["hashed_password"]):
            return None
        
        return create_access_token(data={"sub": username, "role": user.get("role", "analyst")})

    def create_user(self, username, password, role="analyst"):
        """Creates a new user."""
        users = self._load_users()
        
        if any(u["username"] == username for u in users):
            return False # User exists

        hashed_password = get_password_hash(password)
        new_user = {
            "username": username,
            "hashed_password": hashed_password,
            "role": role,
            "created_at": datetime.now()
        }
        
        users.append(new_user)
        self._save_users(users)
        return True

    def change_password(self, username, old_password, new_password):
        """Updates the user's password."""
        users = self._load_users()
        user_idx = next((i for i, u in enumerate(users) if u["username"] == username), -1)
        
        if user_idx == -1:
            return False
        
        user = users[user_idx]
        if not verify_password(old_password, user["hashed_password"]):
            return False
        
        new_hash = get_password_hash(new_password)
        users[user_idx]["hashed_password"] = new_hash
        self._save_users(users)
        return True

    def ensure_admin_user(self):
        """Ensures the default admin exists on startup."""
        users = self._load_users()
        if not any(u["username"] == "admin" for u in users):
            print("[Auth] Seeding default admin user (Local Box)...")
            self.create_user("admin", "admin", role="admin")

auth_service = AuthService()
