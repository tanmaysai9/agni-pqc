import os
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt

from config import JWT_SECRET, SUPPORTED_SCHEMES

JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = int(os.getenv("JWT_EXPIRY_HOURS", "24"))

MOCK_WALLETS = {
    "0xA1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2": {
        "name": "Researcher Alpha",
        "color": "#3B82F6",
    },
    "0xC3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4": {
        "name": "Analyst Beta",
        "color": "#10B981",
    },
    "0xE5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6": {
        "name": "Operator Gamma",
        "color": "#F59E0B",
    },
    # Dedicated wallet for the external uploader on the standalone qp-service.
    # Append-only: tests index MOCK_WALLETS positionally, never reorder.
    "0x9A8B7C6D5E4F9A8B7C6D5E4F9A8B7C6D5E4F9A8B": {
        "name": "External Uploader",
        "color": "#EF4444",
    },
}


def create_token(address: str) -> dict:
    if address not in MOCK_WALLETS:
        raise ValueError("Unknown wallet address")

    wallet = MOCK_WALLETS[address]
    now = datetime.now(timezone.utc)
    payload = {
        "sub": address,
        "name": wallet["name"],
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=JWT_EXPIRY_HOURS)).timestamp()),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return {
        "token": token,
        "address": address,
        "name": wallet["name"],
        "expires_at": (now + timedelta(hours=JWT_EXPIRY_HOURS)).isoformat(),
    }


def verify_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def get_address_from_token(token: str) -> Optional[str]:
    payload = verify_token(token)
    if payload:
        return payload.get("sub")
    return None
