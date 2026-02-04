"""
Application Entry Point
-----------------------
This file serves as the launchpad for the application.
It imports the constructed application from the API Gateway.
"""
import uvicorn
import os
import sys

# Ensure backend package is in path (Appends Project Root)
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the app to expose it to uvicorn if run as 'main:app'
from backend.api_gateway import app

if __name__ == "__main__":
    # Launch Uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
