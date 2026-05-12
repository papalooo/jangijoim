from fastapi import WebSocket
from typing import Dict, List
import json

class ConnectionManager:
    """
    WebSocket 연결을 관리하고 실시간 메시지 브로드캐스트를 담당하는 싱글톤 매니저
    """
    def __init__(self):
        # job_id 별로 활성화된 WebSocket 연결 리스트 관리
        self.active_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, job_id: str):
        await websocket.accept()
        if job_id not in self.active_connections:
            self.active_connections[job_id] = []
        self.active_connections[job_id].append(websocket)
        print(f"📡 [WS] New connection for Job: {job_id}")

    def disconnect(self, websocket: WebSocket, job_id: str):
        if job_id in self.active_connections:
            if websocket in self.active_connections[job_id]:
                self.active_connections[job_id].remove(websocket)
            if not self.active_connections[job_id]:
                del self.active_connections[job_id]
        print(f"📡 [WS] Disconnected for Job: {job_id}")

    async def send_personal_message(self, message: dict, websocket: WebSocket):
        await websocket.send_json(message)

    async def broadcast(self, job_id: str, message: dict):
        """
        특정 job_id에 연결된 모든 클라이언트에게 메시지 전송
        """
        if job_id in self.active_connections:
            # 메시지 전송 중 연결이 끊긴 경우를 대비하여 복사본 사용
            for connection in self.active_connections[job_id][:]:
                try:
                    await connection.send_json(message)
                except Exception as e:
                    print(f"⚠️ [WS] Broadcast failed for a client: {e}")
                    self.disconnect(connection, job_id)

# 싱글톤 인스턴스
manager = ConnectionManager()
