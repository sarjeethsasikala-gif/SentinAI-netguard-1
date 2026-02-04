"""
Project: SentinAI NetGuard
Module: WebSocket Connection Manager
Description: 
    Manages active WebSocket connections for real-time dashboard updates.
    Implements the Singleton pattern to be shared across the API application.
"""
from typing import List
from fastapi import WebSocket

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        print(f"[WS] Client connected. Total: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            print(f"[WS] Client disconnected. Total: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        """Sends a JSON message to all connected clients."""
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                print(f"[WS] Failed to send to client: {e}")
                # We might want to remove dead connections here, but disconnect() usually handles it
                
# Global Instance
manager = ConnectionManager()
