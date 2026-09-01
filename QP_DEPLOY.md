# Secure Question Paper Vault — Standalone Deployment Guide (qp-service)

Deploys the SSS question-paper upload/reconstruct service as a **standalone
product** on `192.168.22.95` (the same box as the satellite backend, but a
separate process, venv, and directory — the satellite deployment in
`~/decentrasec/backend` is untouched).

Topology:

```
External uploader (public internet)
        │  curl -k https://<public-ip>:8443   (self-signed TLS)
        ▼
Router: public 8443 ──► 192.168.22.95:8443   (public 443 stays with satellite)
        ▼
Caddy site :8443 (tls internal) ──► 127.0.0.1:8100
        ▼
qp-service (uvicorn app:app, /opt/qp-service, own venv)
        │  shares (32 B each, SSS)
        ▼
Private IPFS nodes 192.168.22.90–94  (shared with satellite — the only
                                      common component; separate CID space)
```

Encrypted blobs (`data/encrypted/<id>.bin`) stay local on `.95` — they are
the only ciphertext copies; back them up or the papers are unrecoverable even
with all shares.

---

## 1. Deploy directory

Deliberately separate from the satellite repo checkout so the two services
never share `.env`/venv state (and `ENABLE_MOCK_WALLET=0` cannot leak into or
out of the satellite product). Copy only what the standalone service needs —
no `satellite/`, no `pipelines/`, no `crypto/DMaya1.7/`, no PIL/numpy/mono.

From the dev machine (`decentrasec/backend/` as cwd):

```bash
ssh crrao@192.168.22.95 "mkdir -p /opt/qp-service/crypto /opt/qp-service/ipfs /opt/qp-service/tests"

scp app.py question_papers.py auth.py config.py store.py mint_token.py \
    requirements-standalone.txt .env.example crrao@192.168.22.95:/opt/qp-service/
scp crypto/__init__.py crypto/sss.py crypto/aes.py crypto/hash.py \
    crrao@192.168.22.95:/opt/qp-service/crypto/
scp ipfs/__init__.py ipfs/node.py crrao@192.168.22.95:/opt/qp-service/ipfs/
scp tests/test_question_papers.py crrao@192.168.22.95:/opt/qp-service/tests/
```

## 2. Venv + dependencies

```bash
ssh crrao@192.168.22.95
cd /opt/qp-service
python3 -m venv venv
./venv/bin/pip install -r requirements-standalone.txt
```

No `mono`, no Pillow/numpy — the SSS path uses only in-memory
`crypto.aes.encrypt/decrypt` (PyCryptodome).

## 3. `.env`

Create `/opt/qp-service/.env`:

```bash
./venv/bin/python -c "import secrets; print('JWT_SECRET=' + secrets.token_hex(32))"
```

```env
JWT_SECRET=<fresh 64-hex above — distinct from the satellite's secret>
ENABLE_MOCK_WALLET=0
JWT_EXPIRY_HOURS=168
CORS_ORIGINS=https://192.168.22.95:8443
NODE_1_IP=192.168.22.90
NODE_2_IP=192.168.22.91
NODE_3_IP=192.168.22.92
NODE_4_IP=192.168.22.93
NODE_5_IP=192.168.22.94
QP_MAX_FILE_SIZE_MB=50
MANIFESTS_FILE=./data/manifests.json
ENCRYPTED_DATA_DIR=./data/encrypted
```

- `ENABLE_MOCK_WALLET=0` is mandatory in prod: anyone could self-mint a
  token via `POST /api/auth/mock-wallet` (wallet addresses are public in the
  repo). Tokens are minted offline instead (step 5).
- `JWT_EXPIRY_HOURS=168` = 1 week; re-mint per batch if upload cadence is low.

## 4. systemd unit

`/etc/systemd/system/qp-service.service` (run as a non-root user, e.g. the
existing `crrao` or a dedicated `qp-service` user — no `--reload`):

```ini
[Unit]
Description=Secure Question Paper Vault (qp-service)
After=network.target

[Service]
User=crrao
WorkingDirectory=/opt/qp-service
ExecStart=/opt/qp-service/venv/bin/uvicorn app:app --host 127.0.0.1 --port 8100
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now qp-service
systemctl status qp-service
curl -s http://127.0.0.1:8100/health
# {"status":"ok","version":"0.1.0","manifests_count":0}
```

## 5. Mint the uploader token (offline)

Works with the mock-wallet route disabled — token to stdout, expiry to stderr:

```bash
cd /opt/qp-service
./venv/bin/python mint_token.py 0x9A8B7C6D5E4F9A8B7C6D5E4F9A8B7C6D5E4F9A8B
```

Send the token (and its expiry) to the external person over a channel
separate from the base URL. This wallet owns only its own uploads; existing
satellite wallets are unaffected.

## 6. Caddy (TLS on :8443)

Generate a self-signed cert for the bare IP (10 years) and hand it to Caddy
explicitly. Do NOT use `tls internal` here: Caddy's internal issuer mints
certs per site name, and a bare-IP/hostnameless site on a non-443 port fails
every handshake with a TLS `internal error` alert.

```bash
sudo mkdir -p /opt/qp-service/tls
sudo openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
  -keyout /opt/qp-service/tls/qp.key -out /opt/qp-service/tls/qp.crt \
  -subj "/CN=192.168.22.95" \
  -addext "subjectAltName=IP:192.168.22.95,IP:127.0.0.1,DNS:localhost"
sudo chown -R caddy:caddy /opt/qp-service/tls
sudo chmod 600 /opt/qp-service/tls/qp.key
```

Replace the Caddyfile with a single site (Caddy must serve only 8443 — do not
let it take 80/443, which belong to the satellite side):

```bash
sudo tee /etc/caddy/Caddyfile > /dev/null <<'EOF'
{
    auto_https disable_redirects
}

:8443 {
    tls /opt/qp-service/tls/qp.crt /opt/qp-service/tls/qp.key
    reverse_proxy 127.0.0.1:8100
}
EOF
sudo systemctl enable --now caddy
sudo systemctl restart caddy
curl -sk https://127.0.0.1:8443/health
```

Record the cert fingerprint for the uploader to pin (`curl -k` skips
verification, so the fingerprint is the MITM mitigation):

```bash
openssl x509 -in /opt/qp-service/tls/qp.crt -noout -fingerprint -sha256
```

## 7. Router / firewall

- Router port-forward: public **8443 → 192.168.22.95:8443** (443 already
  forwards to the satellite backend).
- `sudo ufw allow 8443/tcp`.
- **Must NOT be WAN-reachable:** 8100 (uvicorn), 5001/8080 (node IPFS),
  9094 (cluster API). Verify from an outside network:

```bash
curl -k --max-time 5 https://<public-ip>:8443/health   # works
curl -k --max-time 5 https://<public-ip>:8100/health   # must time out
```

## 8. Backups

`/opt/qp-service/data/` holds `manifests.json` + the encrypted blobs. The
blobs are the **only ciphertext copies**: losing them loses the papers even
with all 5 shares on IPFS. Back the directory up (offline copy, same
sensitivity as the plaintext papers).

---

## Handover pack for the external uploader

1. **Base URL:** `https://<public-ip>:8443` — self-signed cert, so every
   request uses `curl -k`. If you were given a SHA-256 fingerprint, you can
   pin it instead of blindly trusting `-k`.
2. **Token:** pre-minted JWT (step 5 above) + its expiry. The token *is*
   your identity — keep it secret; it can upload and reconstruct your docs
   until it expires.
3. **Upload** (fields: `file` ext ∈ pdf,doc,docx,png,jpg,jpeg; `n` 2–16;
   `k` with 2 ≤ k ≤ n; file ≤ 50 MB):

   ```bash
   curl -k -X POST "https://<public-ip>:8443/api/question-papers/upload" \
     -H "Authorization: Bearer <TOKEN>" \
     -F "file=@question_paper.pdf" -F "n=5" -F "k=3"
   ```

   `200` returns `{id, scheme:"SSS", n, k, sha256, encrypted_size,
   shares[{index,node,cid}], created_at}` — archive `id` + `sha256` as your
   receipt.

   Errors: `401` missing/invalid token · `413` file too large ·
   `415` extension not allowed · `422` bad n/k or empty file ·
   `502` storage node unreachable during share distribution.

4. **Reconstruct** (owner-only, same token that uploaded):

   ```bash
   curl -k -X POST "https://<public-ip>:8443/api/question-papers/<ID>/reconstruct" \
     -H "Authorization: Bearer <TOKEN>" \
     -o recovered.pdf
   ```

   Response headers include `X-Integrity: verified` and `X-Shares-Used`.
   Byte-compare against the original / check `sha256sum` matches the receipt.

5. **Smoke test first:** `curl -k https://<public-ip>:8443/health`.

---

## Validation checklist (post-deploy)

On `.95` / LAN:

- [ ] `systemctl status qp-service` — active
- [ ] `curl -k https://<public-ip>:8443/health` — `{"status":"ok",...}`
- [ ] `curl -k https://<public-ip>:8443/api/nodes` — 5/5 `online`
      (satellite backend on 443 still healthy — untouched)

From an outside network:

- [ ] Minted token uploads n=5 k=3 → 200 with 5 shares
- [ ] Reconstruct → byte-identical, `sha256sum` matches receipt
- [ ] `POST /api/auth/mock-wallet` → **404** (route disabled)
- [ ] `:8100` not reachable from WAN; satellite 443 unaffected

## Known flagged issues (pre-existing, accepted for this deployment)

- Self-signed TLS is MITM-able if the uploader blindly uses `-k`;
  fingerprint pinning is the offered mitigation.
- Public 8443 adds scan surface; exposure is one minimal FastAPI service,
  mock-wallet off, distinct strong `JWT_SECRET`.
- Out of scope: API-key auth, rate limiting, per-custodian share retrieval,
  UI, domain/ACME, any satellite-product changes.
