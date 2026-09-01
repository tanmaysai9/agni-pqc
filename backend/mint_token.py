"""Offline JWT minter for qp-service.

Mints a token without any network call, so it works while the mock-wallet
route is disabled in production:

    python mint_token.py 0x9A8B7C6D5E4F9A8B7C6D5E4F9A8B7C6D5E4F9A8B

The token goes to stdout (capturable); the expiry goes to stderr.
"""

import sys

from auth import create_token


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit("usage: python mint_token.py <wallet-address>")
    try:
        issued = create_token(sys.argv[1])
    except ValueError as e:
        sys.exit(f"error: {e}")
    print(issued["token"])
    print(f"expires_at: {issued['expires_at']}", file=sys.stderr)


if __name__ == "__main__":
    main()
