# Secure Distributed Storage of Satellite Imagery

A post-quantum-oriented, distributed storage system for satellite imagery. Files are encrypted locally with **AES-256-GCM**; only the small encryption key is protected using **threshold secret sharing** and distributed across a private **IPFS** swarm — no single node ever holds enough to reconstruct anything on its own.

## How it works

- Each file is compressed and encrypted locally (AES-256-GCM). The encrypted file never leaves the owner's storage.
- The encryption key is split using a non-linear (k-of-n) secret sharing scheme and distributed across independent storage nodes via a private IPFS network.
- Reconstruction requires retrieving a quorum of key shares, recombining the key, decrypting, and verifying integrity via SHA-256.
- Each upload is anchored with a Merkle root / transaction hash for tamper-evidence.

## Stack

FastAPI backend · Private IPFS cluster · React/Vite frontend · Wallet-based auth

## Demo dataset

Includes a satellite imagery module (Sentinel-2 scenes) running through the same secure storage pipeline, browsable in the UI.

## Setup

See `SETUP.md` for local deployment instructions.
