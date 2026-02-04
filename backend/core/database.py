"""
Project: AegisCore
Module: Persistence Adapter (Hybrid)
Description:
    Provides a unified interface for data retrieval using MongoDB (Atlas)
    with a seamless fallback to Local JSON storage (Resiliency Mode).
"""

import json
import os
from typing import List, Dict, Any, Optional
from pymongo import MongoClient, DESCENDING
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from backend.core.config import config

class DataAccessLayer:
    """
    Singleton orchestration for persistent storage (MongoDB + Local Fallback).
    """
    
    _instance = None
    _mongo_client = None
    _db = None
    _collection = None
    _is_local_mode = True
    _memory_cache: Optional[List[Dict]] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DataAccessLayer, cls).__new__(cls)
            cls._instance._initialize_connection()
        return cls._instance

    def _initialize_connection(self):
        """Attempts to connect to MongoDB. Falls back to local mode on failure."""
        try:
            print(f"[Persistence] Connecting to MongoDB: {config.MONGO_URI.split('@')[-1]}") # Log safe URI
            self._mongo_client = MongoClient(config.MONGO_URI, serverSelectionTimeoutMS=3000)
            
            # fast check
            self._mongo_client.admin.command('ismaster')
            
            self._db = self._mongo_client[config.DB_NAME]
            self._collection = self._db[config.COLLECTION_NAME]
            self._is_local_mode = False
            print(f"[Persistence] Connected to MongoDB Atlas: {config.DB_NAME}")
        except (ConnectionFailure, ServerSelectionTimeoutError) as e:
            print(f"[Persistence] MongoDB Unreachable. Enabling Resiliency Mode (Local JSON). Error: {e}")
            self._is_local_mode = True

    def get_db_handle(self):
        """Returns the raw MongoDB database handle if active."""
        return self._db if not self._is_local_mode else None

    def _read_local_data(self) -> List[Dict]:
        """Reads data from the local JSON file."""
        if self._memory_cache is not None:
             return self._memory_cache

        if os.path.exists(config.JSON_DB_PATH):
            try:
                with open(config.JSON_DB_PATH, 'r') as f:
                    data = json.load(f)
                    self._memory_cache = data
                    return data
            except Exception as e:
                print(f"[Persistence] Local Read Failed: {e}")
                return []
        return []

    def query_security_events(self, limit: int = 100, projection: Dict = None) -> List[Dict]:
        """
        Retrieves security telemetry events from active storage.
        """
        if not self._is_local_mode:
            try:
                # MongoDB Query
                cursor = self._collection.find({}, projection or {"_id": 0}).sort('timestamp', DESCENDING)
                if limit and limit > 0:
                    cursor = cursor.limit(limit)
                return list(cursor)
            except Exception as e:
                print(f"[Persistence] Mongo Query Failed: {e}. Falling back to local.")
                return self._query_local_events(limit)
        
        return self._query_local_events(limit)

    def _query_local_events(self, limit: int = 100) -> List[Dict]:
        data = self._read_local_data()
        sorted_data = sorted(data, key=lambda x: x.get('timestamp', ''), reverse=True)
        if limit and limit > 0:
            return sorted_data[:limit]
        return sorted_data

    def query_security_events_by_timerange(self, start_time: str, end_time: str, projection: Dict = None) -> List[Dict]:
        """
        Retrieves security events within a specified ISO timestamp range.
        inclusive start, exclusive end.
        """
        if not self._is_local_mode:
            try:
                query = {
                    "timestamp": {
                        "$gte": start_time,
                        "$lt": end_time
                    }
                }
                cursor = self._collection.find(query, projection or {"_id": 0}).sort('timestamp', DESCENDING)
                return list(cursor)
            except Exception as e:
                print(f"[Persistence] Mongo Timerange Query Failed: {e}.")
                # Fallback to local
        
        # Local Fallback
        data = self._read_local_data()
        filtered = []
        for event in data:
            ts = event.get('timestamp', '')
            if start_time <= ts < end_time:
                filtered.append(event)
        
        return sorted(filtered, key=lambda x: x.get('timestamp', ''), reverse=True)

    def save_event(self, event_data: Dict):
        """
        Saves a single event. 
        Notes: In local mode, this might be expensive if done frequently.
        """
        if not self._is_local_mode:
            try:
                # Use provided ID or generate one if missing? 
                # Usually log_generator provides an ID.
                self._collection.update_one(
                    {"id": event_data["id"]},
                    {"$set": event_data},
                    upsert=True
                )
                return
            except Exception as e:
                print(f"[Persistence] Mongo Write Failed: {e}")
        
        # Local Save
        self._save_local_event(event_data)

    def _save_local_event(self, event_data: Dict):
        data = self._read_local_data()
        
        # Check if update or insert
        existing_idx = next((i for i, x in enumerate(data) if x.get("id") == event_data.get("id")), -1)
        if existing_idx >= 0:
            data[existing_idx] = event_data
        else:
            data.append(event_data)
            
        self.update_fallback_cache(data)

    def update_fallback_cache(self, data: List[Dict]):
        """Persists full state to local storage."""
        self._memory_cache = data
        os.makedirs(os.path.dirname(config.JSON_DB_PATH), exist_ok=True)
        try:
            with open(config.JSON_DB_PATH, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"[Persistence] Write Failed: {e}")

# Global Accessor
db = DataAccessLayer()

# Bridge for legacy code compatibility
class LegacyBridge:
    def __init__(self, dal):
        self.dal = dal

    def get_db(self):
        return self.dal.get_db_handle()
    
    def fetch_data(self, limit=100, projection=None):
        return self.dal.query_security_events(limit, projection)
    
    def save_fallback(self, data):
        return self.dal.update_fallback_cache(data)

    def query_security_events_by_timerange(self, start_time, end_time, projection=None):
        return self.dal.query_security_events_by_timerange(start_time, end_time, projection)
        
    def query_events_by_timerange(self, start_time, end_time):
        return self.dal.query_security_events_by_timerange(start_time, end_time)

# Overwrite the export with the bridge wrapping the singleton
db = LegacyBridge(db)
