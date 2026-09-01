import mimetypes
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import Response

from auth import verify_token
from config import (
    NODE_NAMES,
    ENCRYPTED_DATA_DIR,
    QP_ALLOWED_EXTENSIONS,
    QP_MAX_FILE_SIZE_MB,
)
from crypto import aes, sss
from crypto.hash import sha256, mock_merkle_root
from ipfs.node import upload_to_node, fetch_from_node
from store import add_manifest, get_manifest

router = APIRouter(prefix="/api/question-papers", tags=["question-papers"])

MIN_K = 2
MAX_N = 16

# Secure share-distribution roadmap (out of scope for this endpoint, by design):
#
# 1. Per-custodian retrieval endpoint: each authorized user fetches only their
#    assigned share after JWT auth plus a role/assignment check (the server
#    maps share index -> custodian identity), so no single caller can walk the
#    full share set through this API.
# 2. End-to-end upgrade path: wrap each share for a custodian public key
#    (X25519/ECIES) at upload time so the server never sees unwrapped shares
#    in transit and custodians never trust the server with usable material.
# 3. Out-of-band delivery of shares via separate channels/persons; never
#    bundle K shares in one response or email.
#
# Known pre-existing issues (flagged, not fixed here): JWT_SECRET defaults to
# "change-me"; CORS combines allow_origins + ["*"] with allow_credentials=True,
# an invalid/dangerous combination.


async def _get_address(request: Request) -> str:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Missing token")
    payload = verify_token(auth[7:])
    if not payload:
        raise HTTPException(401, "Invalid or expired token")
    return payload["sub"]


def _validate_params(n: int, k: int):
    if not (MIN_K <= k <= n <= MAX_N):
        raise HTTPException(
            422, f"Require {MIN_K} <= k <= n <= {MAX_N}, got k={k}, n={n}"
        )


def _validate_filename(filename: str | None) -> str:
    name = filename or ""
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext not in QP_ALLOWED_EXTENSIONS:
        raise HTTPException(
            415,
            f"Extension '.{ext}' not allowed; permitted: "
            + ", ".join(sorted(QP_ALLOWED_EXTENSIONS)),
        )
    return name


@router.post("/upload")
async def upload(
    address: str = Depends(_get_address),
    file: UploadFile = File(...),
    n: int = Form(...),
    k: int = Form(...),
):
    _validate_params(n, k)
    file_name = _validate_filename(file.filename)

    max_bytes = QP_MAX_FILE_SIZE_MB * 1024 * 1024
    plaintext = bytearray()
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        plaintext.extend(chunk)
        if QP_MAX_FILE_SIZE_MB > 0 and len(plaintext) > max_bytes:
            sss.zeroize(plaintext)
            raise HTTPException(413, f"File exceeds {QP_MAX_FILE_SIZE_MB}MB limit")
    if not plaintext:
        raise HTTPException(422, "Empty file")

    # Single-use AES-256 key per document: os.urandom-backed, never logged,
    # never persisted. Key material lives only in the bytearrays zeroized in
    # the finally block below (best-effort; see crypto.sss.zeroize).
    key = bytearray(aes.generate_key())
    doc_id = str(uuid4())
    blob_path = None
    try:
        file_hash = sha256(bytes(plaintext))
        blob = aes.encrypt(bytes(plaintext), bytes(key))
        sss.zeroize(plaintext)

        ENCRYPTED_DATA_DIR.mkdir(parents=True, exist_ok=True)
        blob_path = ENCRYPTED_DATA_DIR / f"{doc_id}.bin"
        blob_path.write_bytes(blob)
        encrypted_size = blob_path.stat().st_size

        shares = sss.split_key(bytes(key), k, n)
        sss.zeroize(key)

        placements = []
        for idx, share_bytes in shares:
            node = NODE_NAMES[(idx - 1) % len(NODE_NAMES)]
            try:
                cid = await upload_to_node(
                    node, share_bytes, f"qp_{doc_id}_{idx}"
                )
            except Exception as e:
                raise HTTPException(502, f"Share distribution failed: {e}")
            placements.append(
                {"index": idx, "node": node, "cid": cid, "size": len(share_bytes)}
            )

        manifest = {
            "id": doc_id,
            "scheme": "SSS",
            "owner_address": address,
            "file_name": file_name,
            "original_size": len(blob) - aes.NONCE_SIZE - aes.TAG_SIZE,
            "encrypted_size": encrypted_size,
            "mime_type": mimetypes.guess_type(file_name)[0] or "application/octet-stream",
            "threshold_k": k,
            "total_shares_n": n,
            "sha256": file_hash,
            "blob_path": str(blob_path),
            "shares": placements,
            "merkle_root": mock_merkle_root([p["cid"] for p in placements]),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        add_manifest(manifest)

        return {
            "id": doc_id,
            "scheme": "SSS",
            "n": n,
            "k": k,
            "sha256": file_hash,
            "encrypted_size": encrypted_size,
            "shares": [
                {"index": p["index"], "node": p["node"], "cid": p["cid"]}
                for p in placements
            ],
            "created_at": manifest["created_at"],
        }
    finally:
        sss.zeroize(plaintext)
        sss.zeroize(key)
        if blob_path is not None and not get_manifest(doc_id):
            try:
                blob_path.unlink(missing_ok=True)
            except OSError:
                pass


@router.post("/{doc_id}/reconstruct")
async def reconstruct(doc_id: str, address: str = Depends(_get_address)):
    manifest = get_manifest(doc_id)
    if not manifest:
        raise HTTPException(404, "Document not found")
    if manifest.get("owner_address", "") != address:
        raise HTTPException(403, "Not authorized to reconstruct this document")
    if manifest.get("scheme") != "SSS":
        raise HTTPException(422, "Document is not an SSS question paper")

    k = manifest.get("threshold_k", 0)
    collected: list[tuple[int, bytes]] = []
    unreachable: list[int] = []
    for entry in sorted(manifest.get("shares", []), key=lambda s: s["index"]):
        if len(collected) >= k:
            break
        try:
            share_bytes = await fetch_from_node(entry["node"], entry["cid"])
            collected.append((entry["index"], share_bytes))
        except Exception:
            unreachable.append(entry["index"])
    if len(collected) < k:
        raise HTTPException(
            502,
            f"Only {len(collected)}/{k} shares reachable "
            f"(unreachable indices: {unreachable}); cannot reconstruct",
        )

    key = bytearray()
    plaintext = bytearray()
    try:
        try:
            blob_bytes = _read_blob(manifest["blob_path"])
        except OSError as e:
            raise HTTPException(502, f"Encrypted blob unavailable: {e}")

        try:
            key = bytearray(sss.combine_shares(collected))
            plaintext = bytearray(aes.decrypt(blob_bytes, bytes(key)))
        except ValueError as e:
            raise HTTPException(
                422, f"Key recovery or integrity verification failed: {e}"
            )

        if sha256(bytes(plaintext)) != manifest.get("sha256"):
            raise HTTPException(502, "Integrity check failed: SHA-256 mismatch")

        return Response(
            content=bytes(plaintext),
            media_type=manifest.get("mime_type", "application/octet-stream"),
            headers={
                "Content-Disposition": (
                    f'attachment; filename="{manifest.get("file_name", doc_id)}"'
                ),
                "X-Integrity": "verified",
                "X-Shares-Used": str(len(collected)),
            },
        )
    finally:
        sss.zeroize(key)
        sss.zeroize(plaintext)


def _read_blob(path: str) -> bytes:
    return Path(path).read_bytes()
