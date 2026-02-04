"""
Project: SentinAI NetGuard
Module: Security Utils
Description: Handles password hashing (bcrypt) and JWT token generation/validation.
License: MIT / Academic Use Only
"""
from datetime import datetime, timedelta
from typing import Optional
import jwt 
from passlib.context import CryptContext
from backend.core.config import config

# Note: In a real app, SECRET_KEY should be loaded from env and highly secure.
# For this academic project, we might default it in config or here.
SECRET_KEY = "academic_project_secret_key_change_in_production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    """Verifies a plain password against the stored hash."""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    """Generates a bcrypt hash for the password."""
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Creates a JWT access token with expiration."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
