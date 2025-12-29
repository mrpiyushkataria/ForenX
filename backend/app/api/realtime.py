# /backend/app/api/realtime.py
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from typing import Dict, List
import asyncio
import json
from datetime import datetime

router = APIRouter()

class ConnectionManager:
    """Manage WebSocket connections for real-time monitoring."""
    
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.alert_history: List[Dict] = []
        
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        
    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
    
    async def send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)
    
    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except:
                pass
    
    async def broadcast_alert(self, alert: Dict):
        """Broadcast security alerts to all connected clients."""
        alert['timestamp'] = datetime.utcnow().isoformat()
        self.alert_history.append(alert)
        
        # Keep only last 1000 alerts
        if len(self.alert_history) > 1000:
            self.alert_history = self.alert_history[-1000:]
        
        await self.broadcast(json.dumps({
            'type': 'alert',
            'data': alert
        }))

manager = ConnectionManager()

@router.websocket("/ws/monitor")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        # Send recent alerts on connect
        recent_alerts = manager.alert_history[-20:]  # Last 20 alerts
        await websocket.send_text(json.dumps({
            'type': 'initial',
            'data': {
                'recent_alerts': recent_alerts,
                'connected_at': datetime.utcnow().isoformat()
            }
        }))
        
        # Keep connection alive
        while True:
            data = await websocket.receive_text()
            # Handle client messages if needed
            await websocket.send_text(json.dumps({
                'type': 'heartbeat',
                'timestamp': datetime.utcnow().isoformat()
            }))
            
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# Simulated real-time log processor
async def simulate_log_ingestion():
    """Simulate real-time log processing for demonstration."""
    import random
    
    suspicious_endpoints = ['/api/users', '/admin', '/wp-login.php', '/phpmyadmin']
    malicious_ips = ['192.168.1.100', '10.0.0.50', '172.16.0.25']
    
    while True:
        await asyncio.sleep(random.uniform(0.5, 3.0))
        
        # Generate simulated alert
        alert = {
            'level': random.choice(['HIGH', 'MEDIUM', 'LOW']),
            'type': random.choice(['SQLi', 'BruteForce', 'Scanner', 'DataExfiltration']),
            'ip': random.choice(malicious_ips),
            'endpoint': random.choice(suspicious_endpoints),
            'message': f"Suspicious activity detected from {random.choice(malicious_ips)}",
            'requests_per_minute': random.randint(10, 500),
            'risk_score': random.randint(30, 95)
        }
        
        await manager.broadcast_alert(alert)

# Start simulation when module loads (in production, replace with actual log tailing)
import asyncio
asyncio.create_task(simulate_log_ingestion())
