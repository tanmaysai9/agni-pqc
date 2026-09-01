import atexit
import os
import shutil
import sys
import tempfile
from pathlib import Path
from uuid import uuid4

import pytest

# Backend modules import each other flat (e.g. `from crypto.aes import ...`),
# so put backend/ on sys.path like benchmark.py does.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Isolate persisted state BEFORE importing config (env is read at import time;
# load_dotenv does not override pre-set variables).
_TMP = tempfile.mkdtemp(prefix="qp_test_")
os.environ["MANIFESTS_FILE"] = str(Path(_TMP) / "manifests.json")
os.environ["ENCRYPTED_DATA_DIR"] = str(Path(_TMP) / "encrypted")
atexit.register(lambda: shutil.rmtree(_TMP, ignore_errors=True))

from fastapi.testclient import TestClient

import question_papers
from crypto import sss
from auth import MOCK_WALLETS
from store import add_manifest
import app as app_module
from app import app

OWNER = list(MOCK_WALLETS)[0]
OTHER = list(MOCK_WALLETS)[1]

PDF_BYTES = b"%PDF-1.4\n%CONFIDENTIAL QUESTION PAPER\n" + os.urandom(2048)


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture
def fake_ipfs(monkeypatch):
    state = {"store": {}, "down": set(), "tamper": set()}

    async def fake_upload(node, data, filename="share"):
        if node in state["down"]:
            raise ConnectionError(f"{node} unreachable")
        cid = f"cid_{uuid4().hex[:12]}"
        state["store"][cid] = bytes(data)
        return cid

    async def fake_fetch(node, cid):
        if node in state["down"]:
            raise ConnectionError(f"{node} unreachable")
        if cid not in state["store"]:
            raise ValueError(f"{cid} not found on {node}")
        data = state["store"][cid]
        if cid in state["tamper"]:
            data = bytes([data[0] ^ 0xFF]) + data[1:]
        return data

    monkeypatch.setattr(question_papers, "upload_to_node", fake_upload)
    monkeypatch.setattr(question_papers, "fetch_from_node", fake_fetch)
    return state


def get_token(client, address):
    r = client.post("/api/auth/mock-wallet", json={"address": address})
    assert r.status_code == 200
    return r.json()["token"]


def upload(client, token, data=PDF_BYTES, name="paper.pdf", n=5, k=3):
    return client.post(
        "/api/question-papers/upload",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": (name, data, "application/pdf")},
        data={"n": str(n), "k": str(k)},
    )


# --- SSS unit tests -------------------------------------------------------


def test_sss_split_combine_roundtrip():
    key = os.urandom(32)
    shares = sss.split_key(key, 3, 5)
    assert [idx for idx, _ in shares] == [1, 2, 3, 4, 5]
    assert all(len(s) == 32 for _, s in shares)
    assert sss.combine_shares([s for s in shares if s[0] in {1, 3, 5}]) == key
    assert sss.combine_shares([s for s in shares if s[0] in {2, 4}]) != key


def test_sss_combine_rejects_single_share():
    key = os.urandom(32)
    shares = sss.split_key(key, 3, 5)
    with pytest.raises(ValueError):
        sss.combine_shares(shares[:1])


def test_sss_combine_rejects_malformed_length():
    with pytest.raises(ValueError):
        sss.combine_shares([(1, b"short"), (2, b"short")])


def test_sss_split_rejects_bad_params():
    key = os.urandom(32)
    with pytest.raises(ValueError):
        sss.split_key(key, 1, 5)
    with pytest.raises(ValueError):
        sss.split_key(key, 4, 3)
    with pytest.raises(ValueError):
        sss.split_key(b"too-short", 2, 3)


def test_zeroize():
    buf = bytearray(os.urandom(64))
    sss.zeroize(buf)
    assert buf == bytearray(len(buf))


# --- API tests ------------------------------------------------------------


def test_round_trip(client, fake_ipfs):
    token = get_token(client, OWNER)
    r = upload(client, token, n=5, k=3)
    assert r.status_code == 200
    body = r.json()
    assert body["scheme"] == "SSS"
    assert body["n"] == 5 and body["k"] == 3
    assert len(body["shares"]) == 5
    for s in body["shares"]:
        assert set(s.keys()) == {"index", "node", "cid"}

    r2 = client.post(
        f"/api/question-papers/{body['id']}/reconstruct",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r2.status_code == 200
    assert r2.content == PDF_BYTES
    assert r2.headers["X-Integrity"] == "verified"
    assert r2.headers["X-Shares-Used"] == "3"
    assert "paper.pdf" in r2.headers["Content-Disposition"]


def test_reconstruct_with_exactly_k_nodes_up(client, fake_ipfs):
    token = get_token(client, OWNER)
    body = upload(client, token, n=5, k=3).json()
    fake_ipfs["down"] = {"NODE-1", "NODE-2"}
    r = client.post(
        f"/api/question-papers/{body['id']}/reconstruct",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200
    assert r.headers["X-Shares-Used"] == "3"
    assert r.content == PDF_BYTES


def test_reconstruct_too_few_shares_502(client, fake_ipfs):
    token = get_token(client, OWNER)
    body = upload(client, token, n=5, k=3).json()
    fake_ipfs["down"] = {"NODE-1", "NODE-2", "NODE-3"}
    r = client.post(
        f"/api/question-papers/{body['id']}/reconstruct",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 502


def test_reconstruct_tampered_share_422(client, fake_ipfs):
    token = get_token(client, OWNER)
    body = upload(client, token, n=2, k=2).json()
    share1_cid = next(s["cid"] for s in body["shares"] if s["index"] == 1)
    fake_ipfs["tamper"].add(share1_cid)
    r = client.post(
        f"/api/question-papers/{body['id']}/reconstruct",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 422


def test_invalid_params(client, fake_ipfs):
    token = get_token(client, OWNER)
    assert upload(client, token, n=5, k=1).status_code == 422
    assert upload(client, token, n=3, k=4).status_code == 422
    assert upload(client, token, n=17, k=3).status_code == 422


def test_bad_extension_415(client, fake_ipfs):
    token = get_token(client, OWNER)
    r = upload(client, token, data=b"MZ...", name="answers.exe")
    assert r.status_code == 415


def test_empty_file_422(client, fake_ipfs):
    token = get_token(client, OWNER)
    r = upload(client, token, data=b"")
    assert r.status_code == 422


def test_oversized_file_413(client, fake_ipfs, monkeypatch):
    monkeypatch.setattr(question_papers, "QP_MAX_FILE_SIZE_MB", 1)
    token = get_token(client, OWNER)
    r = upload(client, token, data=b"x" + os.urandom(1024 * 1024))
    assert r.status_code == 413


def test_auth_required(client, fake_ipfs):
    files = {"file": ("paper.pdf", PDF_BYTES, "application/pdf")}
    r = client.post(
        "/api/question-papers/upload", files=files, data={"n": "5", "k": "3"}
    )
    assert r.status_code == 401
    r = client.post(
        "/api/question-papers/upload",
        headers={"Authorization": "Bearer bogus"},
        files=files,
        data={"n": "5", "k": "3"},
    )
    assert r.status_code == 401


def test_non_owner_forbidden(client, fake_ipfs):
    owner_token = get_token(client, OWNER)
    other_token = get_token(client, OTHER)
    body = upload(client, owner_token, n=5, k=3).json()
    r = client.post(
        f"/api/question-papers/{body['id']}/reconstruct",
        headers={"Authorization": f"Bearer {other_token}"},
    )
    assert r.status_code == 403


def test_reconstruct_unknown_id_404(client, fake_ipfs):
    token = get_token(client, OWNER)
    r = client.post(
        "/api/question-papers/does-not-exist/reconstruct",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 404


def test_reconstruct_non_sss_manifest_422(client, fake_ipfs):
    token = get_token(client, OWNER)
    manifest = {
        "id": "dmaya-doc",
        "scheme": "DMAYA",
        "owner_address": OWNER,
        "threshold_k": 3,
        "shares": [],
    }
    add_manifest(manifest)
    r = client.post(
        "/api/question-papers/dmaya-doc/reconstruct",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 422


def test_existing_endpoints_still_work(client, fake_ipfs):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_mock_wallet_disabled_returns_404(client, monkeypatch):
    monkeypatch.setattr(app_module, "ENABLE_MOCK_WALLET", False)
    try:
        r = client.post("/api/auth/mock-wallet", json={"address": OWNER})
        assert r.status_code == 404
    finally:
        app_module.ENABLE_MOCK_WALLET = True
