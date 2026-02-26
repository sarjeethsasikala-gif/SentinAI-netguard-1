"""
Project: SentinAI NetGuard
Module: Dependencies
Description:
    FastAPI dependencies for route protection.
    Handles JWT validation and user context retrieval.
"""
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from backend.core.security import SECRET_KEY, ALGORITHM
from backend.services.auth_service import auth_service

# Defines that the client must send a Token in the "Authorization: Bearer <token>" header
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login")

def get_current_user(token: str = Depends(oauth2_scheme)):
    """
    Validates the JWT token.
    If valid, returns the user dictionary.
    If invalid, raises 401 Unauthorized.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
        
    # In a full DB app, we would fetch the user from DB here to ensure they still exist/are active.
    # For now, we trust the token's claim but verifying against auth_service is safer.
    user = auth_service.get_user(username)
    
    if user is None:
        raise credentials_exception
        
    return user
