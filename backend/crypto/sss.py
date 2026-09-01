from Crypto.Protocol.SecretSharing import Shamir

KEY_SIZE = 32
HALF_SIZE = 16
SHARE_SIZE = 32
MIN_K = 2


def split_key(key: bytes, k: int, n: int) -> list[tuple[int, bytes]]:
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key must be exactly {KEY_SIZE} bytes, got {len(key)}")
    if not (MIN_K <= k <= n):
        raise ValueError(f"Require {MIN_K} <= k <= n, got k={k}, n={n}")

    shares_lo = Shamir.split(k, n, key[:HALF_SIZE])
    shares_hi = Shamir.split(k, n, key[HALF_SIZE:])

    combined: list[tuple[int, bytes]] = []
    for (idx_lo, lo), (idx_hi, hi) in zip(shares_lo, shares_hi):
        if idx_lo != idx_hi:
            raise ValueError("Share index mismatch between key halves")
        combined.append((idx_lo, lo + hi))
    return combined


def combine_shares(shares: list[tuple[int, bytes]]) -> bytes:
    if len(shares) < MIN_K:
        raise ValueError(f"Need at least {MIN_K} shares to combine, got {len(shares)}")
    indices = [idx for idx, _ in shares]
    if len(set(indices)) != len(indices):
        raise ValueError("Duplicate share indices")
    for idx, share in shares:
        if len(share) != SHARE_SIZE:
            raise ValueError(
                f"Share {idx} must be exactly {SHARE_SIZE} bytes, got {len(share)}"
            )

    halves_lo = [(idx, share[:HALF_SIZE]) for idx, share in shares]
    halves_hi = [(idx, share[HALF_SIZE:]) for idx, share in shares]
    return Shamir.combine(halves_lo) + Shamir.combine(halves_hi)


def zeroize(buf: bytearray) -> None:
    # Best-effort in-place overwrite. In CPython, bytes are immutable and the
    # interpreter/GC may hold copies (function args, interned buffers, AES
    # internals), so erasure cannot be guaranteed the way it can in C/Rust.
    # Tight scoping of key-material bytearrays plus this overwrite reduces the
    # window, but is NOT a hard guarantee.
    if isinstance(buf, bytearray) and buf:
        buf[:] = bytes(len(buf))
