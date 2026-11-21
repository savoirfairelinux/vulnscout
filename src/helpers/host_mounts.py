# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Container-side client of the host folder helper (see ``host_mount_helper``)."""

import os

from . import host_mount_helper as protocol
from .host_mount_helper import ALIAS_RE, ALIAS_RULE

HELPER_DIRECTORY = "host-helper"
CALL_TIMEOUT = protocol.SEARCH_TIME_LIMIT + 20.0
UNAVAILABLE_MESSAGE = (
    "Host folder helper is not running. On the container host, run './vulnscout ai-context helper start'."
)
# Helper error code -> HTTP status.
HTTP_STATUS = {
    "invalid": 400, "forbidden": 403, "not_found": 404, "unavailable": 409, "limit": 400,
    "busy": 503, "internal": 502,
}


class HostHelperUnavailable(RuntimeError):
    """The helper socket is missing or does not answer."""

    def __init__(self, message: str = UNAVAILABLE_MESSAGE):
        super().__init__(message)
        self.message = message


class HostHelperError(RuntimeError):
    """The helper rejected a request."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message

    @property
    def http_status(self) -> int:
        return HTTP_STATUS.get(self.code, 502)


def socket_path() -> str:
    configured = os.getenv("VULNSCOUT_HOST_HELPER_SOCKET")
    if configured:
        return configured
    cache_dir = os.getenv("VULNSCOUT_CACHE_DIR", "/cache/vulnscout")
    return os.path.join(cache_dir, HELPER_DIRECTORY, protocol.SOCKET_NAME)


def validate_alias(alias: object) -> str:
    if not isinstance(alias, str) or not ALIAS_RE.fullmatch(alias):
        raise ValueError(ALIAS_RULE)
    return alias


def validate_pattern(pattern: str) -> None:
    """Apply the helper's file-pattern limits before sending a request; raises ValueError."""
    try:
        protocol.compile_pattern(pattern)
    except protocol.HelperError as exc:
        raise ValueError(exc.message) from None


def call(operation: str, timeout: float = CALL_TIMEOUT, **params: object) -> dict:
    """Run one helper operation; raises HostHelperUnavailable or HostHelperError."""
    path = socket_path()
    # Reads never create filesystem paths: a missing socket simply means no helper.
    if not os.path.exists(path):
        raise HostHelperUnavailable()
    try:
        reply = protocol.request(path, {"op": operation, **params}, timeout=timeout)
    except (OSError, ValueError) as exc:
        raise HostHelperUnavailable(f"{UNAVAILABLE_MESSAGE} ({exc.__class__.__name__})") from exc
    if reply.get("protocol") != protocol.PROTOCOL_VERSION:
        raise HostHelperUnavailable(
            "Incompatible host folder helper. On the host, run './vulnscout ai-context helper restart'."
        )
    if not reply.get("ok"):
        raise HostHelperError(str(reply.get("code") or "internal"), str(reply.get("error") or "Helper error."))
    result = reply.get("result")
    if not isinstance(result, dict):
        raise HostHelperUnavailable("Host folder helper returned an invalid reply.")
    return result
