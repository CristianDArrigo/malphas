"""
FastAPI local API server.
Bound to 127.0.0.1 only. Never exposed externally.
WebSocket for real-time message push.
"""

import hmac
import os
import re
import secrets
import tempfile

from fastapi import (
    Body,
    FastAPI,
    File,
    Form,
    HTTPException,
    Request,
    Response,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, field_validator

from .files import MAX_FILE_BYTES
from .node import MalphasNode

# Hosts accepted in the Host header. Binding to 127.0.0.1 is not enough on
# its own: a malicious web page can use DNS rebinding to make the browser
# resolve an attacker domain to 127.0.0.1 and reach this API. Pinning the
# Host header to loopback names closes that.
_ALLOWED_HOSTS = frozenset({"127.0.0.1", "localhost"})


def create_app(
    node: MalphasNode,
    static_dir: str,
    *,
    token: str | None = None,
) -> FastAPI:
    """Build the local control API.

    `token` is a bearer secret required on every /api request and the /ws
    socket. If None, a fresh one is generated. It is returned via
    `app.state.api_token` so the launcher can hand it to the local UI
    out-of-band. Localhost binding alone is NOT an authorization boundary:
    any other local user/process, or any web page in the user's browser,
    can otherwise drive the node (read history, send as the user, exfil
    keys). The token also defeats CSRF: a cross-site "simple request"
    cannot set the Authorization header, and any request that does set it
    triggers a CORS preflight that non-localhost origins fail.
    """
    api_token = token or secrets.token_urlsafe(32)

    app = FastAPI(
        title="Malphas",
        docs_url=None,   # disable swagger — no need to expose
        redoc_url=None,
    )
    app.state.api_token = api_token

    # Only allow localhost origins; pin the header allowlist (no "*") so a
    # foreign origin cannot get a token-bearing preflight approved.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost", "http://127.0.0.1"],
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "X-Malphas-Token", "Content-Type"],
    )

    def _token_ok(provided: str | None) -> bool:
        if not provided:
            return False
        return hmac.compare_digest(provided, api_token)

    def _extract_token(headers) -> str | None:
        auth = headers.get("authorization")
        if auth and auth.lower().startswith("bearer "):
            return auth[7:]
        return headers.get("x-malphas-token")

    @app.middleware("http")
    async def _guard(request: Request, call_next):
        # DNS-rebinding defense: Host must be a loopback name.
        host = (request.headers.get("host") or "").rsplit(":", 1)[0]
        if host and host not in _ALLOWED_HOSTS:
            return JSONResponse({"detail": "bad host"}, status_code=400)
        # Auth: every /api route requires the bearer token. Static assets
        # under "/" stay public (showcase only). OPTIONS is exempt so the
        # CORS preflight (which browsers send without Authorization) can be
        # answered by the CORS middleware.
        if request.method != "OPTIONS" and request.url.path.startswith("/api"):
            if not _token_ok(_extract_token(request.headers)):
                return JSONResponse({"detail": "unauthorized"}, status_code=401)
        return await call_next(request)

    ws_clients: set[WebSocket] = set()

    # File transfer state, parallel to MalphasCLI._pending_offers /
    # _completed_files. The web API and the CLI are mutually exclusive
    # entrypoints (one process picks --mode), so duplicating the state
    # here is fine and keeps each surface self-contained.
    pending_offers: dict[str, tuple[str, dict]] = {}      # file_id -> (from_id, offer)
    completed_files: dict[str, tuple[str, str, bytes]] = {}  # file_id -> (from_id, name, data)

    async def _ws_broadcast(message: dict) -> None:
        dead = set()
        for ws in ws_clients:
            try:
                await ws.send_json(message)
            except Exception:
                dead.add(ws)
        ws_clients.difference_update(dead)

    # Register message callback to push via WebSocket
    async def _push_message(from_id: str, content: str) -> None:
        await _ws_broadcast({"type": "message", "from": from_id, "content": content})

    async def _push_file_offer(from_id: str, offer: dict) -> None:
        fid = offer.get("file_id", "")
        if not fid:
            return
        pending_offers[fid] = (from_id, offer)
        await _ws_broadcast({"type": "file_offer", "from": from_id, "offer": offer})

    async def _push_file_complete(file_id: str, data: bytes) -> None:
        offer_entry = pending_offers.pop(file_id, None)
        if offer_entry is not None:
            from_id, offer = offer_entry
            name = offer.get("name", "file.bin")
        else:
            from_id, name = "?", "file.bin"
        completed_files[file_id] = (from_id, name, data)
        await _ws_broadcast({
            "type": "file_complete",
            "file_id": file_id,
            "from": from_id,
            "name": name,
            "size": len(data),
        })

    node.on_message(_push_message)
    node.on_file_offer(_push_file_offer)
    node.on_file_complete(_push_file_complete)

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

        @field_validator("host")
        @classmethod
        def validate_host(cls, v):
            # Constrain to a hostname / IPv4 / .onion grammar. The local API
            # is authenticated (token), but validating the host still blocks
            # control characters, embedded credentials, and obvious
            # injection from reaching asyncio.open_connection / the SOCKS
            # layer, and keeps the SSRF surface to plain TCP connects.
            if not v or len(v) > 253:
                raise ValueError("invalid host")
            if not re.fullmatch(r"[A-Za-z0-9._\-]+", v):
                raise ValueError("host has invalid characters")
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

    class FileIdRequest(BaseModel):
        file_id: str

        @field_validator("file_id")
        @classmethod
        def validate_file_id(cls, v):
            # FileTransferManager generates file_id via secrets.token_hex(16) → 32 hex.
            # We accept any 16+ hex character string to allow CLI-style truncation.
            if not re.fullmatch(r"[0-9a-f]{16,64}", v):
                raise ValueError("file_id must be 16-64 lowercase hex chars")
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

    # --- File transfer ---

    @app.post("/api/files/send")
    async def files_send(
        peer_id: str = Form(...),
        file: UploadFile = File(...),
    ):
        if not re.fullmatch(r"[0-9a-f]{40}", peer_id):
            raise HTTPException(status_code=400, detail="invalid peer_id")
        if not node.discovery.get_peer(peer_id):
            raise HTTPException(status_code=404, detail="peer not in routing table")

        # Save the upload to a temp file so we can hand a path to OutgoingFile.
        # Bounded memory: chunked write. Bounded DISK: abort once the upload
        # exceeds MAX_FILE_BYTES instead of writing it all out and only
        # checking the cap afterwards (disk-fill DoS).
        fd, tmp_path = tempfile.mkstemp(prefix="malphas-api-")
        try:
            written = 0
            with os.fdopen(fd, "wb") as f:
                while True:
                    block = await file.read(64 * 1024)
                    if not block:
                        break
                    written += len(block)
                    if written > MAX_FILE_BYTES:
                        raise HTTPException(
                            status_code=413,
                            detail=f"file exceeds {MAX_FILE_BYTES} byte cap",
                        )
                    f.write(block)

            file_id = await node.send_file(peer_id, tmp_path)
            if file_id is None:
                raise HTTPException(
                    status_code=503,
                    detail="send_file failed (peer offline, file too large, or no circuit)",
                )
            return {"file_id": file_id}
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    @app.get("/api/files")
    async def files_list():
        return {
            "pending": [
                {"file_id": fid, "from": from_id, "offer": offer}
                for fid, (from_id, offer) in pending_offers.items()
            ],
            "completed": [
                {"file_id": fid, "from": from_id, "name": name, "size": len(data)}
                for fid, (from_id, name, data) in completed_files.items()
            ],
        }

    @app.post("/api/files/accept")
    async def files_accept(req: FileIdRequest = Body(...)):
        entry = pending_offers.get(req.file_id)
        if not entry:
            raise HTTPException(status_code=404, detail="no pending offer with that file_id")
        from_id, offer = entry
        ok = node.accept_file_offer(offer)
        if not ok:
            raise HTTPException(status_code=400, detail="malformed offer")
        del pending_offers[req.file_id]
        # Tell the sender we're ready so it streams the chunks now.
        await node.send_file_resume(from_id, offer["file_id"])
        return {"status": "accepted"}

    @app.post("/api/files/reject")
    async def files_reject(req: FileIdRequest = Body(...)):
        if req.file_id not in pending_offers:
            raise HTTPException(status_code=404, detail="no pending offer with that file_id")
        del pending_offers[req.file_id]
        return {"status": "rejected"}

    @app.get("/api/files/{file_id}/download")
    async def files_download(file_id: str):
        if not re.fullmatch(r"[0-9a-f]{16,64}", file_id):
            raise HTTPException(status_code=400, detail="invalid file_id")
        entry = completed_files.get(file_id)
        if not entry:
            raise HTTPException(status_code=404, detail="no completed file with that id")
        from_id, name, data = entry
        # Drop the in-RAM copy after first download to honor the
        # zero-disk-by-default policy of the rest of the codebase.
        del completed_files[file_id]
        # Sanitize the filename for the Content-Disposition header.
        safe_name = re.sub(r"[^A-Za-z0-9._\-]", "_", name)[:128] or "file.bin"
        return Response(
            content=data,
            media_type="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{safe_name}"'},
        )

    @app.websocket("/ws")
    async def websocket_endpoint(ws: WebSocket):
        # Host + token check before accepting. Browsers cannot set custom
        # headers on a WebSocket, so the token travels as a query param
        # (?token=...); it is constant-time compared.
        host = (ws.headers.get("host") or "").rsplit(":", 1)[0]
        if host and host not in _ALLOWED_HOSTS:
            await ws.close(code=1008)
            return
        if not _token_ok(ws.query_params.get("token")):
            await ws.close(code=1008)
            return
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
