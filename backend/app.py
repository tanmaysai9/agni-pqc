"""Standalone entrypoint for the Secure Question Paper Vault (qp-service).

Deliberately minimal: /health, the env-gated mock-wallet auth route, and the
question-papers (SSS) router. No satellite/DMaya pipeline, no SPA, no mono.

Deployment: runs behind uvicorn on 127.0.0.1:8100, exposed via Caddy on :8443
(see decentrasec/QP_DEPLOY.md). `main.py` remains the satellite product.
"""

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware

from auth import MOCK_WALLETS, create_token
from config import CORS_ORIGINS, ENABLE_MOCK_WALLET
from question_papers import router as question_papers_router
from store import load_manifests

app = FastAPI(title="Secure Question Paper Vault", version="0.1.0")

# Unlike main.py, no ["*"] + allow_credentials=True combination: with
# credentials disabled the wildcard would still be unsafe to combine, and a
# curl-only client needs neither.
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(question_papers_router)


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "version": "0.1.0",
        "manifests_count": len(load_manifests()),
    }


@app.post("/api/auth/mock-wallet")
async def mock_wallet_connect(request: Request):
    # Read the module global at request time (not at import) so deployments
    # and tests can flip it without restarting the module.
    if not ENABLE_MOCK_WALLET:
        raise HTTPException(404, "Not found")
    body = await request.json()
    address = body.get("address", "")
    if address not in MOCK_WALLETS:
        raise HTTPException(400, "Invalid address format")
    return create_token(address)
