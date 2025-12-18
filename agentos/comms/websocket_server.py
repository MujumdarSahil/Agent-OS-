"""
WebSocket Server - Real-time collaboration for multi-agent interactions
"""

from typing import Dict, Any, Optional, List, Callable
import asyncio
import json
from enum import Enum
from datetime import datetime


class EventType(Enum):
    """WebSocket event types"""
    PROPOSAL = "proposal"
    VOTE = "vote"
    MESSAGE = "message"
    TOOL_REQUEST = "tool_request"
    EXECUTION_UPDATE = "execution_update"
    STATUS_UPDATE = "status_update"


class WebSocketServer:
    """
    WebSocket server for real-time agent collaboration.
    Supports channels: per-agent, per-squad, per-mission.
    """
    
    def __init__(self, host: str = "localhost", port: int = 8765):
        self.host = host
        self.port = port
        self.connections: Dict[str, Any] = {}  # connection_id -> websocket
        self.channels: Dict[str, List[str]] = {}  # channel_name -> [connection_ids]
        self.event_handlers: Dict[EventType, List[Callable]] = {}
        self.server = None
    
    async def start(self):
        """Start WebSocket server"""
        try:
            import websockets
        except ImportError:
            print("Warning: websockets not installed. WebSocket server disabled.")
            return
        
        async def handler(websocket, path):
            connection_id = str(id(websocket))
            self.connections[connection_id] = websocket
            
            try:
                # Subscribe to default channel
                await self._subscribe(connection_id, "default")
                
                async for message in websocket:
                    await self._handle_message(connection_id, message)
            except Exception as e:
                print(f"WebSocket error: {e}")
            finally:
                await self._unsubscribe_all(connection_id)
                if connection_id in self.connections:
                    del self.connections[connection_id]
        
        import websockets
        self.server = await websockets.serve(handler, self.host, self.port)
        print(f"WebSocket server started on ws://{self.host}:{self.port}")
    
    async def stop(self):
        """Stop WebSocket server"""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
    
    async def _handle_message(self, connection_id: str, message: str):
        """Handle incoming WebSocket message"""
        try:
            data = json.loads(message)
            event_type = EventType(data.get("type", "message"))
            payload = data.get("payload", {})
            
            # Call event handlers
            handlers = self.event_handlers.get(event_type, [])
            for handler in handlers:
                await handler(connection_id, payload)
            
        except Exception as e:
            print(f"Error handling message: {e}")
    
    async def _subscribe(self, connection_id: str, channel: str):
        """Subscribe connection to a channel"""
        if channel not in self.channels:
            self.channels[channel] = []
        if connection_id not in self.channels[channel]:
            self.channels[channel].append(connection_id)
    
    async def _unsubscribe(self, connection_id: str, channel: str):
        """Unsubscribe connection from a channel"""
        if channel in self.channels:
            if connection_id in self.channels[channel]:
                self.channels[channel].remove(connection_id)
    
    async def _unsubscribe_all(self, connection_id: str):
        """Unsubscribe from all channels"""
        for channel in list(self.channels.keys()):
            await self._unsubscribe(connection_id, channel)
    
    async def broadcast(
        self,
        channel: str,
        event_type: EventType,
        payload: Dict[str, Any]
    ):
        """
        Broadcast event to all connections in a channel.
        
        Args:
            channel: Channel name
            event_type: Event type
            payload: Event payload
        """
        if channel not in self.channels:
            return
        
        message = {
            "type": event_type.value,
            "payload": payload,
            "timestamp": datetime.now().isoformat(),
        }
        
        message_json = json.dumps(message)
        
        # Send to all connections in channel
        disconnected = []
        for connection_id in self.channels[channel]:
            websocket = self.connections.get(connection_id)
            if websocket:
                try:
                    await websocket.send(message_json)
                except Exception:
                    disconnected.append(connection_id)
            else:
                disconnected.append(connection_id)
        
        # Clean up disconnected
        for conn_id in disconnected:
            await self._unsubscribe(conn_id, channel)
    
    async def send_to_agent(self, agent_id: str, event_type: EventType, payload: Dict[str, Any]):
        """Send event to a specific agent"""
        await self.broadcast(f"agent:{agent_id}", event_type, payload)
    
    async def send_to_squad(self, squad_id: str, event_type: EventType, payload: Dict[str, Any]):
        """Send event to a squad"""
        await self.broadcast(f"squad:{squad_id}", event_type, payload)
    
    async def send_to_mission(self, mission_id: str, event_type: EventType, payload: Dict[str, Any]):
        """Send event to a mission"""
        await self.broadcast(f"mission:{mission_id}", event_type, payload)
    
    def register_handler(self, event_type: EventType, handler: Callable):
        """Register event handler"""
        if event_type not in self.event_handlers:
            self.event_handlers[event_type] = []
        self.event_handlers[event_type].append(handler)

