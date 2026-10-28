"""Generate `docs/api/openapi.yaml` and `docs/api/postman-collection.json` from the live FastAPI app."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import yaml

from app.main import app

REPO_ROOT = Path(__file__).resolve().parents[3]
DOCS_API_DIR = REPO_ROOT / "docs" / "api"


def _build_postman_collection(schema: Dict[str, Any]) -> Dict[str, Any]:
    items_by_tag: Dict[str, List[Dict[str, Any]]] = {}

    for path, methods in sorted((schema.get("paths") or {}).items()):
        for method, op in sorted(methods.items()):
            if method.lower() not in {"get", "post", "patch", "put", "delete"}:
                continue
            tag = (op.get("tags") or ["General"])[0]
            raw_path = path.lstrip("/")
            path_parts = [p for p in raw_path.split("/") if p]

            req_obj: Dict[str, Any] = {
                "method": method.upper(),
                "header": [
                    {"key": "Authorization", "value": "Bearer {{access_token}}", "type": "text"},
                    {"key": "Content-Type", "value": "application/json", "type": "text"},
                ],
                "url": {
                    "raw": "{{base_url}}/" + raw_path,
                    "host": ["{{base_url}}"],
                    "path": path_parts,
                },
                "description": op.get("description") or op.get("summary") or "",
            }
            if method.upper() in {"POST", "PATCH", "PUT"}:
                req_obj["body"] = {"mode": "raw", "raw": "{}"}

            items_by_tag.setdefault(tag, []).append(
                {
                    "name": f"{method.upper()} {path} — {op.get('summary') or op.get('operationId') or ''}".strip(" —"),
                    "request": req_obj,
                }
            )

    folders = [
        {"name": tag, "item": endpoints}
        for tag, endpoints in sorted(items_by_tag.items())
    ]

    return {
        "info": {
            "name": f"{schema.get('info', {}).get('title', 'Antiphishing Platform')} API v{schema.get('info', {}).get('version', '2.0.0')}",
            "description": schema.get("info", {}).get("description", ""),
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        "variable": [
            {"key": "base_url", "value": "http://localhost:8000"},
            {"key": "access_token", "value": ""},
            {"key": "gateway_api_key", "value": ""},
            {"key": "n8n_service_key", "value": ""},
        ],
        "item": folders,
    }


def generate_api_artifacts() -> None:
    DOCS_API_DIR.mkdir(parents=True, exist_ok=True)
    schema = app.openapi()

    openapi_path = DOCS_API_DIR / "openapi.yaml"
    openapi_yaml = yaml.safe_dump(schema, sort_keys=False, allow_unicode=True)
    openapi_path.write_text(openapi_yaml, encoding="utf-8")

    postman_path = DOCS_API_DIR / "postman-collection.json"
    postman_collection = _build_postman_collection(schema)
    postman_path.write_text(
        json.dumps(postman_collection, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"Generated {openapi_path} ({len(openapi_yaml)} bytes, {len(schema.get('paths', {}))} paths)")
    print(f"Generated {postman_path} ({postman_path.stat().st_size} bytes)")


if __name__ == "__main__":
    generate_api_artifacts()
