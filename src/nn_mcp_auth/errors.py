"""Error types shared across nn-mcp-auth."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


class NnMcpAuthError(Exception):
    """Base for all library-raised errors."""

    error_code = "nn_mcp_auth_error"

    def __init__(
        self,
        message: str,
        *,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.details: dict[str, Any] = dict(details) if details is not None else {}

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "error": True,
            "error_code": self.error_code,
            "message": self.message,
        }
        if self.details:
            payload["details"] = self.details
        return payload


class ConfigurationError(NnMcpAuthError):
    error_code = "configuration_error"


class ValidationError(NnMcpAuthError):
    error_code = "validation_error"
