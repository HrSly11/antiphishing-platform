"""Structured JSON logging with a correlation id carried through a ContextVar."""
import json
import logging
import sys
from contextvars import ContextVar
from datetime import datetime, timezone

correlation_id_ctx: ContextVar[str] = ContextVar("correlation_id", default="-")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "correlation_id": correlation_id_ctx.get(),
        }
        extra = getattr(record, "extra_fields", None)
        if extra:
            entry.update(extra)
        if record.exc_info:
            entry["exc"] = self.formatException(record.exc_info)
        return json.dumps(entry, ensure_ascii=False)


def configure_logging(level: int = logging.INFO) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)
    logging.getLogger("uvicorn.access").handlers = [handler]


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
