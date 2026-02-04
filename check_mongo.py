import os
import sys
from dotenv import load_dotenv
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, OperationFailure

# Load env variables
base_dir = os.path.dirname(os.path.abspath(__file__))
env_path = os.path.join(base_dir, '.env')
load_dotenv(env_path)

uri = os.getenv("MONGO_URI")
print(f"Testing Connection to: {uri}")

try:
    client = MongoClient(uri, serverSelectionTimeoutMS=5000)
    # The ismaster command is cheap and does not require auth.
    client.admin.command('ismaster')
    print("SUCCESS: Connected to MongoDB Server!")
    
    # Try to access the specific database
    db = client.get_database("threat_detection")
    print(f"Database 'threat_detection' accessible.")
    
except ConnectionFailure:
    print("FAILURE: Server not available.")
except OperationFailure as e:
    print(f"FAILURE: Authentication/Operation failed: {e}")
except Exception as e:
    print(f"FAILURE: Unexpected error: {e}")
