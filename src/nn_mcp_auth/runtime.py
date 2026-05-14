"""JSON logging helpers shared by NN MCP servers."""

from __future__ import annotations

import json
import logging
import os
import time
from collections.abc import Mapping
from typing import Any

_SENSITIVE_KEYS = frozenset(
    {
        "access_token",
        "api_key",
        "authorization",
        "client_secret",
        "credentials",
        "developer_token",
        "github_token",
        "meta_app_secret",
        "meta_token",
        "password",
        "refresh_token",
        "secret",
        "token",
        "webhook_secret",
        "x-api-key",
    }
)
_REDACTED = "[REDACTED]"
DEFAULT_LOG_LEVEL = "INFO"


def _sanitize_value(value: Any, *, key_name: str | None = None) -> Any:
    if key_name is not None and key_name.lower() in _SENSITIVE_KEYS:
        return _REDACTED
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, Mapping):
        return {
            str(k): _sanitize_value(v, key_name=str(k)) for k, v in value.items()
        }
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_sanitize_value(item) for item in value]
    return str(value)


def sanitize_log_fields(fields: Mapping[str, Any]) -> dict[str, Any]:
    return {
        str(key): _sanitize_value(value, key_name=str(key))
        for key, value in fields.items()
    }


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "event": getattr(record, "event", record.getMessage()),
            "level": record.levelname,
            "logger": record.name,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
        }
        if isinstance(record.msg, Mapping):
            payload.update(sanitize_log_fields(record.msg))
        else:
            payload["message"] = record.getMessage()
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def log_json(logger: logging.Logger, level: int, event: str, **fields: Any) -> None:
    logger.log(level, {"event": event, **fields})


def configure_logging(
    *,
    logger_name: str,
    level_name: str | None = None,
) -> logging.Logger:
    env_level_name = os.getenv("LOG_LEVEL") or DEFAULT_LOG_LEVEL
    resolved = (level_name or env_level_name).upper()
    level = getattr(logging, resolved, logging.INFO)
    logger = logging.getLogger(logger_name)
    logger.setLevel(level)
    logger.propagate = False

    marker = f"_nn_mcp_auth_json_handler_{logger_name}"
    for handler in logger.handlers:
        if getattr(handler, marker, False):
            handler.setLevel(level)
            return logger

    handler = logging.StreamHandler()
    handler.setLevel(level)
    handler.setFormatter(JsonFormatter())
    setattr(handler, marker, True)
    logger.handlers = [handler]
    return logger
