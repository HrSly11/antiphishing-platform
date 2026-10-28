"""Cryptographic secret generator for JWT, Gateway API keys, and n8n HMAC webhook secrets."""
from __future__ import annotations

import argparse
import secrets


def generate_secret_bundle() -> dict[str, str]:
    """Generate high-entropy URL-safe secrets compliant with banking key-rotation policies."""
    return {
        "SECRET_KEY": secrets.token_urlsafe(48),
        "GATEWAY_API_KEY": secrets.token_urlsafe(32),
        "N8N_SERVICE_KEY": secrets.token_urlsafe(32),
        "N8N_WEBHOOK_SECRET": secrets.token_hex(32),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate rotated secrets for .env / Kubernetes Secrets.")
    parser.add_argument("--env-format", action="store_true", help="Print KEY=VALUE lines suitable for .env")
    args = parser.parse_args()
    bundle = generate_secret_bundle()
    if args.env_format:
        for k, v in bundle.items():
            print(f"{k}={v}")
    else:
        for k, v in bundle.items():
            print(f"{k}: {v}")


if __name__ == "__main__":
    main()
