import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

IPFS_CLUSTER_API = os.getenv("IPFS_CLUSTER_API", "http://localhost:9094")
IPFS_GATEWAY = os.getenv("IPFS_GATEWAY", "http://localhost:8080")
IPFS_CLUSTER_USER = os.getenv("IPFS_CLUSTER_USER", "admin")
IPFS_CLUSTER_PASS = os.getenv("IPFS_CLUSTER_PASS", "Agni@123")
JWT_SECRET = os.getenv("JWT_SECRET", "change-me")
CORS_ORIGINS = [
    o.strip()
    for o in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",")
    if o.strip()
]
MANIFESTS_FILE = os.getenv("MANIFESTS_FILE", "./data/manifests.json")
ENCRYPTED_DATA_DIR = Path(os.getenv("ENCRYPTED_DATA_DIR", "./data/encrypted"))
DEMO_DATA_DIR = os.getenv("DEMO_DATA_DIR", "./data/demo-data")
MAX_FILE_SIZE_MB = int(os.getenv("MAX_FILE_SIZE_MB", "0"))
IPFS_UPLOAD_TIMEOUT = int(os.getenv("IPFS_UPLOAD_TIMEOUT", "300"))
IPFS_FETCH_TIMEOUT = int(os.getenv("IPFS_FETCH_TIMEOUT", "120"))

NODE_NAMES = ["NODE-1", "NODE-2", "NODE-3", "NODE-4", "NODE-5"]

NODE_IPS = {
    "NODE-1": os.getenv("NODE_1_IP", "192.168.22.90"),
    "NODE-2": os.getenv("NODE_2_IP", "192.168.22.91"),
    "NODE-3": os.getenv("NODE_3_IP", "192.168.22.92"),
    "NODE-4": os.getenv("NODE_4_IP", "192.168.22.93"),
    "NODE-5": os.getenv("NODE_5_IP", "192.168.22.94"),
}

NODE_DAEMON_PORT = int(os.getenv("NODE_DAEMON_PORT", "5001"))
NODE_GATEWAY_PORT = int(os.getenv("NODE_GATEWAY_PORT", "8080"))

QP_MAX_FILE_SIZE_MB = int(os.getenv("QP_MAX_FILE_SIZE_MB", "50"))
QP_ALLOWED_EXTENSIONS = {
    e.strip().lower()
    for e in os.getenv("QP_ALLOWED_EXTENSIONS", "pdf,doc,docx,png,jpg,jpeg").split(",")
    if e.strip()
}

# Standalone qp-service: when "0", POST /api/auth/mock-wallet returns 404 so
# tokens can only be minted offline via mint_token.py (prod hardening; the
# repo's wallet addresses are public).
ENABLE_MOCK_WALLET = os.getenv("ENABLE_MOCK_WALLET", "1") == "1"

SUPPORTED_SCHEMES = {"DMAYA": True, "SSS": True}
