import os
import sys
import dns.resolver
from dotenv import load_dotenv
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, OperationFailure, ConfigurationError

# Load env variables
base_dir = os.path.dirname(os.path.abspath(__file__))
env_path = os.path.join(base_dir, '.env')
load_dotenv(env_path)

uri = os.getenv("MONGO_URI")
print(f"Testing Connection to: {uri.split('@')[-1]}") # Print safe part

# 1. Test DNS Resolution
try:
    domain = uri.split('@')[1].split('/')[0]
    print(f"Resolving DNS for: {domain}")
    answers = dns.resolver.resolve(domain, 'A')
    for rdata in answers:
        print(f" - Resolved IP: {rdata}")
except Exception as e:
    print(f"DNS Resolution Failed: {e}")
    # Continue anyway as pymongo handles SRV

# 2. Test Connection
try:
    # Try adding tlsAllowInvalidCertificates=True for testing (sometimes helps on corp networks)
    client = MongoClient(uri, serverSelectionTimeoutMS=5000, tlsAllowInvalidCertificates=True)
    print("Attempting to connect with TLS verification disabled (test)...")
    
    info = client.admin.command('ismaster')
    print("SUCCESS: Connected to MongoDB Server!")
    print(f"Server Version: {info.get('version')}")
    
except ConnectionFailure as e:
    print(f"FAILURE: Server not available.")
    print(f"Details: {e}")
except ConfigurationError as e:
    print(f"FAILURE: Configuration Error (check dnspython): {e}")
except Exception as e:
    print(f"FAILURE: Unexpected error: {e}")
