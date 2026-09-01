import os
import json
import base64
import io
from io import BytesIO
from uuid import uuid4
from pathlib import Path

from fastapi import FastAPI, Request, UploadFile, File, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.background import BackgroundTask
from PIL import Image

Image.MAX_IMAGE_PIXELS = None

from config import CORS_ORIGINS, NODE_NAMES, NODE_IPS
from auth import create_token, verify_token, MOCK_WALLETS
from store import (
    get_manifest,
    get_manifests_for_address,
    delete_manifest,
    load_manifests,
    add_manifest,
)
from pipelines.upload import run_upload, get_upload_status
from pipelines.reconstruct import reconstruct_by_id
from satellite.routes import router as satellite_router
from question_papers import router as question_papers_router

app = FastAPI(title="Secure Distributed Storage of Satellite Imagery", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS + ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(satellite_router)
app.include_router(question_papers_router)


async def _get_address(request: Request) -> str:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Missing token")
    payload = verify_token(auth[7:])
    if not payload:
        raise HTTPException(401, "Invalid or expired token")
    return payload["sub"]


def _cleanup_temp(path: str):
    try:
        os.unlink(path)
    except Exception:
        pass


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "version": "0.1.0",
        "manifests_count": len(load_manifests()),
    }


@app.post("/api/auth/mock-wallet")
async def mock_wallet_connect(request: Request):
    body = await request.json()
    address = body.get("address", "")
    if address not in MOCK_WALLETS:
        raise HTTPException(400, "Invalid address format")
    return create_token(address)


@app.post("/api/thumbnail")
async def thumbnail(file: UploadFile = File(...)):
    ext = (file.filename or "").rsplit(".", 1)[-1].lower() if "." in (file.filename or "") else ""
    if ext in ("tif", "tiff"):
        chunk = await file.read(100 * 1024 * 1024)
    else:
        chunk = await file.read(10 * 1024 * 1024)
    try:
        img = Image.open(io.BytesIO(chunk))
        if img.mode not in ("RGB", "RGBA", "L"):
            img = img.convert("RGB")
        img.thumbnail((256, 256))
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=60)
        thumb_b64 = base64.b64encode(buf.getvalue()).decode("ascii")
        return {"thumbnail": thumb_b64}
    except Exception:
        return {"thumbnail": None}


@app.post("/api/upload")
async def upload(
    address: str = Depends(_get_address),
    file: UploadFile = File(...),
):
    import asyncio
    import tempfile

    tmp_path = tempfile.mktemp(suffix="_upload")
    with open(tmp_path, "wb") as f:
        while True:
            chunk = await file.read(64 * 1024 * 1024)
            if not chunk:
                break
            f.write(chunk)

    upload_id = str(uuid4())
    asyncio.create_task(
        run_upload(
            upload_id,
            tmp_path,
            file.filename or "unknown",
            address,
        )
    )
    return {"id": upload_id, "status": "processing"}


@app.get("/api/upload/{upload_id}/status")
async def upload_status(upload_id: str):
    status = get_upload_status(upload_id)
    if not status:
        raise HTTPException(404, "Upload not found")
    return {"id": upload_id, **status}


@app.get("/api/archive")
async def archive(address: str = Depends(_get_address)):
    files = get_manifests_for_address(address)
    result = []
    for m in files:
        nodes = {}
        for n in NODE_NAMES:
            entry = {"cid": None, "healthy": False}
            for ks in m.get("key_shares", []):
                if ks.get("node") == n:
                    entry["cid"] = ks["cid"]
                    entry["healthy"] = True
            nodes[n] = entry

        result.append(
            {
                "id": m["id"],
                "file_name": m.get("file_name", ""),
                "original_size": m.get("original_size", 0),
                "total_shares_n": m.get("total_shares_n", len(m.get("key_shares", []))),
                "merkle_root": m.get("merkle_root", ""),
                "owner_address": m.get("owner_address", ""),
                "nodes": nodes,
                "created_at": m.get("created_at", ""),
                "upload_duration_ms": m.get("upload_duration_ms"),
                "reconstruct_duration_ms": m.get("reconstruct_duration_ms"),
                "stage_durations": m.get("stage_durations", {}),
                "thumbnail": m.get("thumbnail"),
            }
        )
    return {"files": result}


@app.post("/api/reconstruct/{manifest_id}")
async def reconstruct(manifest_id: str, address: str = Depends(_get_address)):
    manifest = get_manifest(manifest_id)
    if not manifest:
        raise HTTPException(404, "Manifest not found")
    if manifest.get("owner_address", "") != address:
        raise HTTPException(403, "Not authorized to reconstruct this file")

    try:
        result = await reconstruct_by_id(manifest_id)
    except ValueError as e:
        import logging
        logging.getLogger("reconstruct").error("Reconstruct ValueError for %s: %s", manifest_id, e)
        raise HTTPException(422, str(e))
    except Exception as e:
        import logging
        logging.getLogger("reconstruct").error("Reconstruct error for %s: %s", manifest_id, e, exc_info=True)
        raise HTTPException(502, f"Reconstruction failed: {e}")

    return FileResponse(
        result["data_path"],
        media_type=result["mime_type"],
        headers={
            "Content-Disposition": f'attachment; filename="{result["file_name"]}"',
            "X-Merkle-Root": result["merkle_root"],
            "X-Integrity": "verified",
            "X-Shares-Used": result["shares_used"],
            "X-Reconstruct-Duration-Ms": str(result["reconstruct_duration_ms"]),
        },
        background=BackgroundTask(lambda p=result["data_path"]: _cleanup_temp(p)),
    )


@app.get("/api/nodes")
async def nodes():
    from ipfs.node import check_node_health
    import asyncio
    health_results = await asyncio.gather(
        *[check_node_health(name) for name in NODE_NAMES]
    )
    node_list = []
    for h in health_results:
        node_list.append({
            "name": h["name"],
            "ip": h["ip"],
            "status": h["status"],
            "peer_id": h.get("peer_id", ""),
            "error": h.get("error"),
        })
    all_online = all(n["status"] == "online" for n in node_list)
    return {"nodes": node_list, "cluster_healthy": all_online}


@app.delete("/api/archive/{manifest_id}")
async def delete_archive_entry(manifest_id: str, address: str = Depends(_get_address)):
    manifest = get_manifest(manifest_id)
    if not manifest:
        raise HTTPException(404, "Not found")
    if manifest.get("owner_address") != address:
        raise HTTPException(403, "Not authorized")
    delete_manifest(manifest_id)
    return {"deleted": True, "id": manifest_id}


static_dir = Path(__file__).parent / "static"
if static_dir.exists() and (static_dir / "index.html").exists():
    app.mount(
        "/assets", StaticFiles(directory=str(static_dir / "assets")), name="assets"
    )

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        fp = static_dir / full_path
        if fp.exists() and fp.is_file():
            return FileResponse(str(fp))
        return FileResponse(str(static_dir / "index.html"))
