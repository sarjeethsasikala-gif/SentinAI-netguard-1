import sys
import os
import traceback

# Add root to path (assuming running from c:/SentinAI-netguard)
sys.path.append(os.getcwd())

print(f"Current CWD: {os.getcwd()}")
print(f"Sys Path: {sys.path}")

try:
    from backend.services.auth_service import auth_service
    print("Auth Service Imported")
    
    print("Attempting authentication...")
    token = auth_service.authenticate_user("admin", "admin")
    print(f"Token: {token}")

except Exception as e:
    print("Caught Exception:")
    traceback.print_exc()
