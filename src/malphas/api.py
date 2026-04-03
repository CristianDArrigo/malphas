"""
FastAPI local API server.
Bound to 127.0.0.1 only. Never exposed externally.
WebSocket for real-time message push.
"""

import asyncio
import json
from typing import Set

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, field_validator
import re

from .node import MalphasNode


def create_app(node: MalphasNode, static_dir: str) -> FastAPI:
    app = FastAPI(
        title="Malphas",
        docs_url=None,   # disable swagger — no need to expose
        redoc_url=None,
    )

    # Only allow localhost origins
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost", "http://127.0.0.1"],
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    ws_clients: Set[WebSocket] = set()

    # Register message callback to push via WebSocket
    async def _push_message(from_id: str, content: str) -> None:
        dead = set()
        for ws in ws_clients:
            try:
                await ws.send_json({"type": "message", "from": from_id, "content": content})
            except Exception:
                dead.add(ws)
        ws_clients.difference_update(dead)

    node.on_message(_push_message)

    # --- Models ---

    class ConnectRequest(BaseModel):
        host: str
        port: int
        peer_id: str
        x25519_pub: str   # hex
        ed25519_pub: str  # hex

        @field_validator("peer_id")
        @classmethod
        def validate_peer_id(cls, v):
            if not re.fullmatch(r"[0-9a-f]{40}", v):
                raise ValueError("peer_id must be 40-char lowercase hex")
            return v

        @field_validator("x25519_pub", "ed25519_pub")
        @classmethod
        def validate_pubkey(cls, v):
            if not re.fullmatch(r"[0-9a-f]{64}", v):
                raise ValueError("pubkey must be 64-char lowercase hex")
            return v

        @field_validator("port")
        @classmethod
        def validate_port(cls, v):
            if not 1 <= v <= 65535:
                raise ValueError("Invalid port")
            return v

    class SendRequest(BaseModel):
        to: str
        content: str

        @field_validator("to")
        @classmethod
        def validate_to(cls, v):
            if not re.fullmatch(r"[0-9a-f]{40}", v):
                raise ValueError("to must be 40-char lowercase hex peer_id")
            return v

        @field_validator("content")
        @classmethod
        def validate_content(cls, v):
            if not v or len(v) > 4096:
                raise ValueError("Content must be 1-4096 chars")
            return v

    # --- Routes ---

    @app.get("/api/identity")
    async def get_identity():
        return {
            "peer_id": node.identity.peer_id,
            "x25519_pub": node.identity.x25519_pub_bytes.hex(),
            "ed25519_pub": node.identity.ed25519_pub_bytes.hex(),
            "port": node.port,
        }

    @app.get("/api/peers")
    async def get_peers():
        return {"peers": node.discovery.all_peers()}

    @app.post("/api/peers/connect")
    async def connect_peer(req: ConnectRequest):
        ok = await node.connect_to_peer(
            req.host,
            req.port,
            req.peer_id,
            bytes.fromhex(req.x25519_pub),
            bytes.fromhex(req.ed25519_pub),
        )
        if not ok:
            raise HTTPException(status_code=503, detail="Connection failed")
        return {"status": "connected"}

    @app.post("/api/messages/send")
    async def send_message(req: SendRequest):
        ok = await node.send_message(req.to, req.content)
        if not ok:
            raise HTTPException(status_code=503, detail="Send failed: peer unreachable or no circuit")
        return {"status": "sent"}

    @app.get("/api/messages/{peer_id}")
    async def get_messages(peer_id: str):
        if not re.fullmatch(r"[0-9a-f]{40}", peer_id):
            raise HTTPException(status_code=400, detail="Invalid peer_id")
        msgs = node.store.get_conversation(node.identity.peer_id, peer_id)
        return {"messages": msgs}

    @app.websocket("/ws")
    async def websocket_endpoint(ws: WebSocket):
        await ws.accept()
        ws_clients.add(ws)
        try:
            while True:
                await ws.receive_text()  # keep-alive
        except WebSocketDisconnect:
            ws_clients.discard(ws)

    # Serve PWA static files
    app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")

    return app
