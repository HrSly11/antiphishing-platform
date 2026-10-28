"""Loader/inspector utility for exported LangFlow v1 JSON graph definitions."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

FLOWS_DIR = Path(__file__).resolve().parents[3] / "langflow" / "flows"


def list_langflow_sandboxes() -> List[Dict[str, Any]]:
    """Return metadata for all versioned LangFlow JSON graphs in `backend/langflow/flows/`."""
    results: List[Dict[str, Any]] = []
    if not FLOWS_DIR.exists():
        return results
    for path in sorted(FLOWS_DIR.glob("*.json")):
        raw = json.loads(path.read_text(encoding="utf-8"))
        graph = raw.get("data") or {}
        results.append(
            {
                "filename": path.name,
                "name": raw.get("name", path.stem),
                "description": raw.get("description", ""),
                "endpoint_name": raw.get("endpoint_name", ""),
                "node_count": len(graph.get("nodes") or []),
                "edge_count": len(graph.get("edges") or []),
            }
        )
    return results
