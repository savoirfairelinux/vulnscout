#!/usr/bin/env python3
# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Unprivileged host-side helper serving attached host folders read-only to VulnScout.

The ``vulnscout`` wrapper starts this script on the container host as the invoking
user (never root). It must stay a standalone, standard-library-only module: the
wrapper runs it with the host's ``python3`` (3.9 or newer) outside the container.

It listens on a private Unix socket (directory ``0700``, socket ``0600``) inside the
VulnScout cache directory, which the container already mounts, so attaching folders
later needs no container restart. Every request is scoped by variant ID and alias:
the helper serves only exact folders approved by a host-side CLI permit, opens every path
component without following symbolic links, and bounds result counts, read sizes,
search time and bytes. No operation creates, changes or deletes anything under an
attached folder; the helper only writes its own registry file.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import hmac
import io
import json
import os
import re
import signal
import socket
import socketserver
import sqlite3
import stat
import struct
import sys
import threading
import time
import uuid
import weakref
from contextlib import closing
from datetime import datetime, timezone
from fnmatch import fnmatchcase, translate
from typing import Any, Callable, Iterator

PROTOCOL_VERSION = 4
SOCKET_NAME = "helper.sock"
REGISTRY_NAME = "registry.json"

MAX_RESPONSE_BYTES = 512 * 1024
MAX_CONTENT_BYTES = 64 * 1024
MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_WALK_ENTRIES = 500_000
LIST_TIME_LIMIT = 10.0
SEARCH_TIME_LIMIT = 20.0
SEARCH_BYTE_BUDGET = 100 * 1024 * 1024
MAX_LIST_LIMIT = 200
MAX_READ_LINES = 200
MAX_SEARCH_RESULTS = 100
MAX_SNIPPET_CHARS = 500
MAX_QUERY_CHARS = 200
MAX_PATTERN_CHARS = 512
# Few wildcards keep glob matching linear enough: a regex match cannot be interrupted by the time limits.
MAX_PATTERN_WILDCARDS = 16
MIN_PYTHON = (3, 9)
MAX_PATH_CHARS = 4096
MAX_ATTACHMENTS_PER_VARIANT = 32
MAX_SESSION_PINS = 128
STAGED_PIN_SECONDS = 300
# Allow a JSON-escaped mount path plus a scoped member path, pattern and request envelope.
MAX_REQUEST_BYTES = 128 * 1024
MAX_CONNECTIONS = 8
CONNECTION_TIMEOUT = 30.0

ALIAS_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,31}")
ALIAS_RULE = "Alias must be 1-32 lowercase letters, digits, '_' or '-', starting with a letter or digit."

# Keep in sync with src/helpers/codebase_directory.py.
_SENSITIVE_NAMES = (
    "*secret*", "*credential*", "*password*", "*token*", "*.pem", "*.key", "*.p12", "*.pfx",
    "*.keystore", "id_rsa*", "id_ed25519*", "id_dsa*", "id_ecdsa*", "kubeconfig",
    "*.kdbx", "*.sqlite*", "*.db", "*~", "*.bak",
)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | _CLOEXEC
_LINK_ERRNOS = (errno.ELOOP, errno.ENOTDIR)
_MOVED = "Attached folder was moved or replaced; attach it again."


class HelperError(Exception):
    """A request failed; ``code`` is one of invalid, forbidden, not_found, unavailable, limit, busy, internal."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class _Exhausted(Exception):
    """A walk exceeded its entry or time budget."""


def _excluded(name: str) -> bool:
    return name.startswith(".") or any(fnmatchcase(name.lower(), pattern) for pattern in _SENSITIVE_NAMES)


def _printable(name: str) -> bool:
    try:
        name.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return not any(ord(char) < 32 or ord(char) == 127 for char in name)


def _string(request: dict, name: str, *, required: bool = True, maximum: int = MAX_PATH_CHARS) -> str:
    value = request.get(name)
    if value is None and not required:
        return ""
    if not isinstance(value, str) or (required and not value):
        raise HelperError("invalid", f"{name} must be a non-empty string.")
    if len(value) > maximum or "\x00" in value:
        raise HelperError("invalid", f"{name} is too long or contains invalid characters.")
    return value


def compile_pattern(pattern: str) -> Callable[[str], bool]:
    """Validate a case-sensitive file-path glob and compile it once for the whole request."""
    if len(pattern) > MAX_PATTERN_CHARS or "\x00" in pattern:
        raise HelperError("invalid", f"File pattern must be at most {MAX_PATTERN_CHARS} characters.")
    if pattern.count("*") + pattern.count("?") > MAX_PATTERN_WILDCARDS:
        raise HelperError("invalid", f"File pattern may contain at most {MAX_PATTERN_WILDCARDS} '*' or '?' wildcards.")
    match = re.compile(translate(pattern)).match
    return lambda path: match(path) is not None


def _pattern(request: dict) -> tuple[Callable[[str], bool], str]:
    pattern = _string(request, "pattern", required=False, maximum=MAX_PATTERN_CHARS) or "*"
    return compile_pattern(pattern), pattern


def _folder_parts(request: dict) -> list[str]:
    """Optional sub-folder of the attachment that scopes a list or search."""
    folder = _string(request, "folder", required=False, maximum=1024)
    return _relative_path(folder.rstrip("/")) if folder else []


def _integer(request: dict, name: str, default: int, minimum: int, maximum: int) -> int:
    value = request.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise HelperError("invalid", f"{name} must be an integer between {minimum} and {maximum}.")
    return value


def _variant_id(request: dict) -> str:
    raw = _string(request, "variant_id", maximum=64)
    try:
        return str(uuid.UUID(raw))
    except ValueError:
        raise HelperError("invalid", "variant_id must be a UUID.") from None


def validate_alias(alias: object) -> str:
    if not isinstance(alias, str) or not ALIAS_RE.fullmatch(alias):
        raise HelperError("invalid", ALIAS_RULE)
    return alias


def _member_path_fits(path: str) -> bool:
    return len(path) <= 1024 and "\\" not in path and _printable(path)


def _relative_path(path: str) -> list[str]:
    """Split a member path, rejecting traversal, absolute paths and excluded components."""
    if not path or not _member_path_fits(path) or path.startswith("/"):
        raise HelperError("invalid", "Path must be a relative path inside the attached folder.")
    parts = path.split("/")
    for part in parts:
        if part in ("", ".", ".."):
            raise HelperError("invalid", "Path must be a relative path inside the attached folder.")
        if _excluded(part):
            raise HelperError("not_found", "Source file not found or excluded.")
    return parts


def _open_absolute(path: str, *, create: bool = False) -> int:
    """Open a canonical absolute directory without following links, including ancestors."""
    fd = os.open("/", _DIRECTORY_FLAGS)
    try:
        for part in path.split("/"):
            if not part:
                continue
            try:
                child = os.open(part, _DIRECTORY_FLAGS, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
                child = os.open(part, _DIRECTORY_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
    except BaseException:
        os.close(fd)
        raise
    return fd


def _sync_directory(path: str) -> None:
    fd = os.open(path, _DIRECTORY_FLAGS)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class _FileHandle(ctypes.Structure):
    # Linux struct file_handle, with room for MAX_HANDLE_SZ opaque bytes.
    _fields_ = [("size", ctypes.c_uint), ("kind", ctypes.c_int), ("data", ctypes.c_ubyte * 128)]


_NAME_TO_HANDLE_AT = getattr(ctypes.CDLL(None), "name_to_handle_at", None)


def _boot_id() -> bytes | None:
    try:
        with open("/proc/sys/kernel/random/boot_id", encoding="ascii") as handle:
            return uuid.UUID(handle.read(64).strip()).bytes
    except (OSError, ValueError):
        return None


def _directory_handle(fd: int, boot: bytes | None) -> str | None:
    """Digest an exportable handle scoped to a non-recycled mount ID within this boot."""
    if boot is None or _NAME_TO_HANDLE_AT is None:
        return None
    handle = _FileHandle()
    handle.size = len(handle.data)
    mount = ctypes.c_uint64()
    # AT_EMPTY_PATH | AT_HANDLE_MNT_ID_UNIQUE: identify this fd, not a second path lookup.
    if _NAME_TO_HANDLE_AT(fd, b"", ctypes.byref(handle), ctypes.byref(mount), 0x1000 | 0x001) != 0:
        return None
    if not 0 < handle.size <= len(handle.data):
        return None
    identity = boot + struct.pack("!Qi", mount.value, handle.kind) + bytes(handle.data[:handle.size])
    return "h" + hashlib.sha256(identity).hexdigest()


class _SessionPin:
    """Own an exact directory descriptor until activation is abandoned or the grant is detached."""

    def __init__(self, fd: int, attachment_id: str):
        self.fd = os.dup(fd)
        self.close = weakref.finalize(self, os.close, self.fd)
        self.attachment_id = attachment_id
        self.expires = time.monotonic() + STAGED_PIN_SECONDS


def _proof_key(directory: str) -> bytes:
    """Publish a complete private key exactly once, including across competing starts."""
    path = os.path.join(directory, ".approval.key")
    if not os.path.exists(path):
        temporary = f"{path}.{uuid.uuid4()}"
        with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as handle:
            try:
                handle.write(os.urandom(32))
                handle.flush()
                os.fsync(handle.fileno())
                try:
                    os.link(temporary, path)
                except FileExistsError:
                    pass
            finally:
                os.unlink(temporary)
    _sync_directory(directory)
    with open(path, "rb") as handle:
        key = handle.read(33)
    if len(key) != 32:
        raise ValueError("Invalid host folder approval key.")
    return key


class Registry:
    """Alias -> host path, per variant, stored in a private host-only JSON file."""

    def __init__(self, state_dir: str):
        self.path = os.path.join(state_dir, REGISTRY_NAME)
        self.lock = threading.Lock()
        self.data: dict[str, dict[str, dict[str, str]]] = {}
        # A detach can arrive before a delayed activation, even for a never-activated ID.
        self._fences = os.path.join(state_dir, "retired.sqlite")
        os.close(os.open(self._fences, os.O_CREAT | os.O_RDWR, 0o600))
        with closing(sqlite3.connect(self._fences)) as conn, conn:
            conn.execute("CREATE TABLE IF NOT EXISTS retired (id TEXT PRIMARY KEY) WITHOUT ROWID")
        rewrite = False
        try:
            with open(self.path, encoding="utf-8") as handle:
                loaded = json.load(handle)
            attachments = loaded.get("attachments") if isinstance(loaded, dict) else None
            if isinstance(attachments, dict):
                rewrite = "retired" in loaded
                if loaded.get("retired"):
                    with closing(sqlite3.connect(self._fences)) as conn, conn:
                        conn.executemany("INSERT OR IGNORE INTO retired VALUES (?)", ((i,) for i in loaded["retired"]))
                for variant_id, aliases in attachments.items():
                    if not isinstance(aliases, dict):
                        continue
                    self.data[variant_id] = {
                        alias: entry for alias, entry in aliases.items()
                        if ALIAS_RE.fullmatch(alias) and isinstance(entry, dict)
                        and isinstance(entry.get("path"), str)
                    }
                    # Rebuild older registries from signed DB bindings, never old root grants.
                    # Also discard approvals fenced before a crash interrupted their JSON removal.
                    for alias, entry in list(self.data[variant_id].items()):
                        if (loaded.get("version") != PROTOCOL_VERSION or entry.get("host_approved") != "yes"
                                or not entry.get("attachment_id") or not entry.get("identity")
                                or self._retired(entry["attachment_id"])):
                            del self.data[variant_id][alias]
                            rewrite = True
        except FileNotFoundError:
            pass
        except (OSError, ValueError) as exc:
            raise ValueError(f"Cannot read helper registry {self.path}: {exc}") from exc
        if rewrite:
            self._save()

    def _retired(self, attachment_id: str) -> bool:
        with closing(sqlite3.connect(self._fences)) as conn:
            return conn.execute("SELECT 1 FROM retired WHERE id=?", (attachment_id,)).fetchone() is not None

    def binding(self, variant_id: str, alias: str) -> dict[str, str] | None:
        with self.lock:
            entry = self.data.get(variant_id, {}).get(alias)
            return entry.copy() if entry else None

    def get(self, variant_id: str, alias: str) -> str | None:
        entry = self.binding(variant_id, alias)
        return entry["path"] if entry else None

    def set(self, variant_id: str, alias: str, path: str, *, attachment_id: str, identity: str) -> None:
        with self.lock:
            aliases = self.data.get(variant_id, {})
            if alias not in aliases and len(aliases) >= MAX_ATTACHMENTS_PER_VARIANT:
                raise HelperError(
                    "limit", f"A variant can have at most {MAX_ATTACHMENTS_PER_VARIANT} attached folders.")
            previous = aliases.get(alias, {})
            if self._retired(attachment_id) or (previous and (
                    previous["attachment_id"] != attachment_id or previous["path"] != path)):
                raise HelperError("unavailable", "Attachment has been detached or replaced.")
            if previous.get("identity") == identity:
                return
            self.data[variant_id] = aliases
            aliases[alias] = {"path": path, "created_at": datetime.now(timezone.utc).isoformat(),
                              "attachment_id": attachment_id, "host_approved": "yes", "identity": identity}
            try:
                self._save()
            except OSError:
                if previous:
                    aliases[alias] = previous
                else:
                    del aliases[alias]
                raise

    def remove(self, variant_id: str, alias: str, *, attachment_id: str,
               retire: bool = False) -> bool:
        with self.lock:
            aliases = self.data.get(variant_id, {})
            entry = aliases.get(alias, {})
            removed = entry.get("attachment_id") == attachment_id
            if retire and attachment_id:
                with closing(sqlite3.connect(self._fences)) as conn, conn:
                    conn.execute("INSERT OR IGNORE INTO retired VALUES (?)", (attachment_id,))
            if not removed:
                return False
            del aliases[alias]
            if not aliases:
                self.data.pop(variant_id, None)
            try:
                self._save()
            except OSError:
                if not (retire and attachment_id):
                    self.data.setdefault(variant_id, {})[alias] = entry
                raise
            return removed

    def _save(self) -> None:
        temporary = f"{self.path}.{os.getpid()}.{threading.get_ident()}.tmp"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _CLOEXEC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump({"version": PROTOCOL_VERSION, "attachments": self.data}, handle, indent=2, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
            _sync_directory(os.path.dirname(self.path))
        except BaseException:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise


def _literal_prefix(pattern: str) -> str:
    """Leading part of a glob that contains no wildcard."""
    for index, char in enumerate(pattern):
        if char in "*?[":
            return pattern[:index]
    return pattern


class _Walk:
    """Sorted depth-first walk of eligible regular files, bounded by entries and time.

    The pattern is applied during the walk so that directories which cannot contain a match
    (their path conflicts with the pattern's literal prefix) are never opened and files that do
    not match are never stat'ed; huge build trees stay cheap for narrow patterns.
    """

    def __init__(self, root_fd: int, time_limit: float, matcher: Callable[[str], bool] | None = None,
                 pattern: str = "*"):
        self.root_fd = root_fd
        self.started = time.monotonic()
        self.deadline = self.started + time_limit
        self.visited = 0
        self.io_errors = 0
        self.skipped_paths = 0
        self.engine = "python"
        self.matcher = matcher
        self.literal = _literal_prefix(pattern)
        self.exact = self.literal == pattern

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.started

    def files(self, base: str) -> Iterator[tuple[str, int]]:
        for path, size in self._files():
            if _member_path_fits(base + path):
                yield path, size
            else:
                self.skipped_paths += 1

    def _files(self) -> Iterator[tuple[str, int]]:
        directory = os.dup(self.root_fd)
        parts = self.literal.split("/")
        try:
            for part in parts[:-1]:
                if not part or _excluded(part):
                    return
                self._tick()
                self.check_time()
                child = os.open(part, _DIRECTORY_FLAGS, dir_fd=directory)
                os.close(directory)
                directory = child
            if self.exact:
                name = parts[-1]
                if name and not _excluded(name):
                    self._tick()
                    info = os.stat(name, dir_fd=directory, follow_symlinks=False)
                    if stat.S_ISREG(info.st_mode):
                        yield self.literal, info.st_size
            else:
                yield from self._walk(directory, self.literal[:len(self.literal) - len(parts[-1])])
            self.check_time()
        except (FileNotFoundError, NotADirectoryError):
            return
        except OSError:
            self.io_errors += 1
        finally:
            os.close(directory)

    def check_time(self) -> None:
        if time.monotonic() > self.deadline:
            raise _Exhausted("time")

    def _may_contain(self, directory: str) -> bool:
        return self.literal.startswith(directory) or directory.startswith(self.literal)

    def _walk(self, directory_fd: int, prefix: str) -> Iterator[tuple[str, int]]:
        entries = []
        exhausted = False
        try:
            with os.scandir(directory_fd) as iterator:
                for entry in iterator:
                    if self.visited >= MAX_WALK_ENTRIES:
                        exhausted = True
                        break
                    self._tick()
                    entries.append(entry)
        except OSError:
            self.io_errors += 1
        entries.sort(key=lambda item: item.name)
        for entry in entries:
            self.check_time()
            if _excluded(entry.name):
                continue
            try:
                is_dir = entry.is_dir(follow_symlinks=False)
                is_file = not is_dir and entry.is_file(follow_symlinks=False)
            except OSError:
                self.io_errors += 1
                continue
            if is_dir:
                if exhausted:
                    continue
                directory = f"{prefix}{entry.name}/"
                if not self._may_contain(directory):
                    continue
                try:
                    child = os.open(entry.name, _DIRECTORY_FLAGS, dir_fd=directory_fd)
                except OSError:
                    self.io_errors += 1
                    continue

                try:
                    yield from self._walk(child, directory)
                finally:
                    os.close(child)
            elif is_file:
                path = f"{prefix}{entry.name}"
                if self.matcher is not None and not self.matcher(path):
                    continue
                try:
                    yield path, entry.stat(follow_symlinks=False).st_size
                except OSError:
                    self.io_errors += 1
                    continue

        if exhausted:
            raise _Exhausted("entries")

    def _tick(self) -> None:
        if self.visited >= MAX_WALK_ENTRIES:
            raise _Exhausted("entries")
        self.visited += 1
        if self.visited % 256 == 0:
            self.check_time()


def _exhausted_message(reason: str, operation: str, walk: "_Walk | None" = None) -> str:
    detail = f" (visited {walk.visited} entries in {walk.elapsed:.1f}s)" if walk else ""
    advice = ("narrow the pattern with a literal folder prefix such as 'build/tmp/work/*/curl/*' "
              "or attach a smaller folder.")
    if reason == "entries":
        return f"The {operation} stopped after visiting {MAX_WALK_ENTRIES} entries{detail}; {advice}"
    if reason == "bytes":
        mebibytes = SEARCH_BYTE_BUDGET / (1024 * 1024)
        return f"The next file would exceed the {mebibytes:g} MiB search byte budget{detail}; narrow the pattern."
    if reason == "results":
        return f"The {operation} reached its match limit{detail}; narrow the query or pattern."
    return f"The {operation} stopped at its time limit{detail}; {advice}"


def _walk_message(message: str | None, walk: _Walk) -> str | None:
    warnings = [message] if message else []
    if walk.io_errors:
        warnings.append(f"Incomplete: {walk.io_errors} I/O error(s) while accessing files or folders.")
    if walk.skipped_paths:
        warnings.append(f"Incomplete: skipped {walk.skipped_paths} file path(s) that cannot be represented.")
    return " ".join(warnings) or None


class Helper:
    """Request dispatcher for exact host-approved attachments."""

    def __init__(self, state_dir: str):
        self.state_dir = state_dir
        self.registry = Registry(state_dir)
        self._key = _proof_key(state_dir)
        self._boot = _boot_id()
        self._pins: dict[str, _SessionPin] = {}
        self._pin_lock = threading.RLock()
        self.operations: dict[str, Callable[[dict], dict]] = {
            "status": self.status, "detach": self.detach,
            "source": self.source, "stage": self.stage, "activate": self.activate,
            "list": self.list_files, "read": self.read, "search": self.search,
        }

    # -- dispatch -----------------------------------------------------------------------------

    def dispatch(self, request: object) -> dict:
        try:
            if not isinstance(request, dict):
                raise HelperError("invalid", "Request must be a JSON object.")
            operation = self.operations.get(request.get("op"))  # type: ignore[arg-type]
            if operation is None:
                raise HelperError("invalid", "Unknown operation; the helper is read-only.")
            return {"ok": True, "result": operation(request)}
        except HelperError as exc:
            return {"ok": False, "code": exc.code, "error": exc.message}
        except Exception as exc:  # pragma: no cover - defensive: never leak tracebacks to clients
            _log(f"internal error: {type(exc).__name__}: {exc}")
            return {"ok": False, "code": "internal", "error": "Internal helper error; see the helper log."}

    # -- path checks --------------------------------------------------------------------------

    def _open_folder(self, path: str) -> int:
        try:
            return _open_absolute(path)
        except FileNotFoundError:
            raise HelperError("not_found", "Host folder not found.") from None
        except PermissionError:
            raise HelperError("unavailable", "Host folder is not readable by the helper user.") from None
        except OSError as exc:
            if exc.errno in _LINK_ERRNOS:
                raise HelperError("unavailable", _MOVED) from None
            raise HelperError("unavailable", "Host folder cannot be opened.") from None

    def expire_pending_pins(self) -> None:
        with self._pin_lock:
            now = time.monotonic()
            for key, pin in list(self._pins.items()):
                if pin.expires <= now:
                    self._pins.pop(key).close()

    def _approval_identity(self, fd: int, attachment_id: str) -> str:
        durable = _directory_handle(fd, self._boot)
        if durable is not None:
            return durable
        with self._pin_lock:
            self.expire_pending_pins()
            info = os.fstat(fd)
            for key, pin in self._pins.items():
                if pin.attachment_id == attachment_id and os.path.samestat(info, os.fstat(pin.fd)):
                    pin.expires = max(pin.expires, time.monotonic() + STAGED_PIN_SECONDS)
                    return key
            if len(self._pins) >= MAX_SESSION_PINS:
                raise HelperError("limit", "Session-only folder limit reached; detach unused folders and retry.")
            key = "s" + uuid.uuid4().hex
            self._pins[key] = _SessionPin(fd, attachment_id)
            return key

    def _open_approved(self, path: str, identity: str) -> int:
        fd = self._open_folder(path)
        try:
            if identity.startswith("s"):
                with self._pin_lock:
                    pin = self._pins.get(identity)
                    if pin is None or pin.expires <= time.monotonic():
                        raise HelperError("unavailable", "Session-only approval expired; reattach with the host CLI.")
                    info = os.fstat(pin.fd)
                    if info.st_nlink and os.path.samestat(info, os.fstat(fd)):
                        # Serve the pinned object, never merely one reporting the same inode.
                        return os.open(".", _DIRECTORY_FLAGS, dir_fd=pin.fd)
            elif _directory_handle(fd, self._boot) == identity:
                return os.dup(fd)
            raise HelperError("unavailable", _MOVED)
        finally:
            os.close(fd)

    def _attachment_fd(self, request: dict) -> int:
        variant_id = _variant_id(request)
        alias = validate_alias(request.get("alias"))
        entry = self.registry.binding(variant_id, alias)
        if entry is None:
            raise HelperError("not_found", f"No folder is attached as '{alias}' for this variant.")
        path = entry["path"]
        if request.get("mount_path", path) != path:
            raise HelperError("forbidden", "Folder does not match the host-approved attachment.")
        return self._open_approved(path, entry["identity"])

    def _scoped_fd(self, request: dict) -> tuple[int, str]:
        """Attachment (or its optional ``folder``) opened without following links, plus the path prefix."""
        parts = _folder_parts(request)
        fd = self._attachment_fd(request)
        current = fd
        try:
            for part in parts:
                child = os.open(part, _DIRECTORY_FLAGS, dir_fd=current)
                os.close(current)
                current = child
        except FileNotFoundError:
            os.close(current)
            raise HelperError("not_found", "Folder not found inside the attached folder.") from None
        except OSError as exc:
            os.close(current)
            if exc.errno in _LINK_ERRNOS:
                raise HelperError("invalid", "Folder is not a directory or is a link.") from None
            raise HelperError("unavailable", "Folder cannot be opened.") from None
        return current, "".join(f"{part}/" for part in parts)

    def status(self, request: dict) -> dict:
        return {"protocol": PROTOCOL_VERSION, "read_only": True}

    def _validate_attach(self, request: dict, attachment_id: str) -> dict:
        variant_id = _variant_id(request)
        alias = validate_alias(request.get("alias"))
        path = _string(request, "path")
        permit = request.get("host_permit")
        # Only the host wrapper can create a permit in this non-mounted directory.
        if not isinstance(permit, str) or not re.fullmatch(r"permit\.[a-zA-Z0-9]{12}", permit):
            raise HelperError("forbidden", "Invalid host attachment permit.")
        try:
            permit_file = os.path.join(self.state_dir, permit, alias)
            with open(permit_file, "rb") as handle:
                approval = handle.read()
        except FileNotFoundError:
            raise HelperError("forbidden", "Host attachment permit has expired.") from None
        if (approval != variant_id.encode() + b"\0" + os.fsencode(path)
                or not os.path.isabs(path) or path == "/" or os.path.realpath(path) != path):
            raise HelperError("forbidden", "Host attachment permit does not authorize this folder.")
        if any(_excluded(part) for part in path.split("/") if part):
            raise HelperError("forbidden", "Hidden or sensitive folders cannot be attached.")
        fd = self._open_folder(path)
        try:
            try:
                os.unlink(permit_file)
            except FileNotFoundError:
                raise HelperError("forbidden", "Host attachment permit has expired.") from None
            identity = self._approval_identity(fd, attachment_id)
        finally:
            os.close(fd)
        return {"variant_id": variant_id, "alias": alias, "path": path, "identity": identity}

    def _proof(self, attachment_id: str, variant_id: str, alias: str, path: str, identity: str) -> str:
        binding = json.dumps(["approval-v4", attachment_id, variant_id, alias, path, identity], separators=(",", ":"))
        return identity + ":" + hmac.digest(self._key, binding.encode("ascii"), "sha256").hex()

    def stage(self, request: dict) -> dict:
        """Validate before the backend transaction; never make the folder accessible here."""
        attachment_id = _string(request, "attachment_id", maximum=36)
        result = self._validate_attach(request, attachment_id)
        result["approval_proof"] = self._proof(attachment_id, **result)
        return result

    def activate(self, request: dict) -> dict:
        variant_id = _variant_id(request)
        alias = validate_alias(request.get("alias"))
        path = _string(request, "path")
        attachment_id = _string(request, "attachment_id", maximum=36)
        proof = request.get("approval_proof")
        if (not isinstance(proof, str)
                or not (match := re.fullmatch(r"(h[a-f0-9]{64}|s[a-f0-9]{32}):[a-f0-9]{64}", proof))
                or not hmac.compare_digest(proof, self._proof(attachment_id, variant_id, alias, path, match[1]))):
            raise HelperError("forbidden", "No valid host approval; reattach this folder with the host CLI.")
        identity = match[1]
        with self._pin_lock:
            os.close(self._open_approved(path, identity))
            self.registry.set(variant_id, alias, path, attachment_id=attachment_id, identity=identity)
            for key, pin in list(self._pins.items()):
                if key == identity:
                    pin.expires = float("inf")
                elif pin.attachment_id == attachment_id and pin.expires == float("inf"):
                    self._pins.pop(key).close()
        return {"path": path}

    def detach(self, request: dict) -> dict:
        variant_id = _variant_id(request)
        alias = validate_alias(request.get("alias"))
        attachment_id = _string(request, "attachment_id", maximum=36)
        with self._pin_lock:
            removed = self.registry.remove(variant_id, alias, attachment_id=attachment_id, retire=True)
            for key, pin in list(self._pins.items()):
                if pin.attachment_id == attachment_id:
                    self._pins.pop(key).close()
        return {"removed": removed}

    def source(self, request: dict) -> dict:
        """Require the current host-approved alias to match the database mount path."""
        _string(request, "mount_path")
        operation = request.get("source_operation")
        if operation not in ("list", "read", "search"):
            raise HelperError("invalid", "Operation must be list, read, or search.")
        return {
            "list": self.list_files,
            "read": self.read,
            "search": self.search,
        }[operation](request)

    def list_files(self, request: dict) -> dict:
        matches_pattern, pattern = _pattern(request)
        offset = _integer(request, "offset", 0, 0, MAX_WALK_ENTRIES)
        limit = _integer(request, "limit", MAX_LIST_LIMIT, 1, MAX_LIST_LIMIT)
        fd, base = self._scoped_fd(request)
        walk = _Walk(fd, LIST_TIME_LIMIT, matches_pattern, pattern)
        files: list[dict] = []
        total = 0
        message = None
        try:
            for path, size in walk.files(base):
                if offset <= total < offset + limit:
                    files.append({"path": base + path, "size": size})
                total += 1
        except _Exhausted as exc:
            message = _exhausted_message(str(exc), "listing", walk)
        finally:
            os.close(fd)
        message = _walk_message(message, walk)
        result: dict[str, Any] = {
            "files": files, "total": total, "truncated": message is not None, "engine": walk.engine,
            "skipped_paths": walk.skipped_paths, "io_errors": walk.io_errors,
            "visited_entries": walk.visited, "elapsed_seconds": round(walk.elapsed, 2),
            "next_offset": offset + limit if offset + limit < total else None,
        }
        if message:
            result["message"] = message
        return _fit_page(result, "files", offset)

    def _read_file(self, root_fd: int, parts: list[str], budget: list[int] | None = None) -> bytes:
        directory_fd = root_fd
        opened: list[int] = []
        try:
            for part in parts[:-1]:
                directory_fd = os.open(part, _DIRECTORY_FLAGS, dir_fd=directory_fd)
                opened.append(directory_fd)
            entry = os.open(parts[-1], os.O_PATH | os.O_NOFOLLOW | _CLOEXEC, dir_fd=directory_fd)
            try:
                if not stat.S_ISREG(os.fstat(entry).st_mode):
                    raise HelperError("invalid", "Directories, links and special files cannot be read.")
                fd = os.open(f"/proc/self/fd/{entry}", os.O_RDONLY | _CLOEXEC)
            finally:
                os.close(entry)
        except FileNotFoundError:
            raise HelperError("not_found", "Source file not found or excluded.") from None
        except OSError as exc:
            if exc.errno in _LINK_ERRNOS:
                raise HelperError("invalid", "Links and special files cannot be read.") from None
            raise HelperError("unavailable", "Source file cannot be opened.") from None
        finally:
            for item in opened:
                os.close(item)
        try:
            info = os.fstat(fd)
            if info.st_size > MAX_FILE_BYTES:
                raise HelperError("limit", "Source file exceeds the maximum readable file size of 10 MiB.")
            if budget is not None and info.st_size > budget[0]:
                raise _Exhausted("bytes")
            limit = MAX_FILE_BYTES + 1
            if budget is not None:
                limit = min(limit, budget[0])
            content = os.read(fd, limit)
            if budget is not None:
                budget[0] -= len(content)
                # A growing file must not spend past the budget, or be searched as if complete.
                if len(content) == limit and budget[0] == 0 and (
                        not limit or len(content) != os.fstat(fd).st_size):
                    raise _Exhausted("bytes")
            if len(content) < info.st_size:
                raise HelperError("unavailable", "Source file could not be read in full.")
        finally:
            os.close(fd)
        if len(content) > MAX_FILE_BYTES:
            raise HelperError("limit", "Source file exceeds the maximum readable file size of 10 MiB.")
        return content

    @staticmethod
    def _text(content: bytes) -> str:
        if b"\x00" in content:
            raise HelperError("invalid", "Source file is binary; only UTF-8 text can be read.")
        try:
            return content.decode("utf-8-sig")
        except UnicodeDecodeError:
            raise HelperError("invalid", "Source file is not UTF-8 text.") from None

    def read(self, request: dict) -> dict:
        path = _string(request, "path", maximum=1024)
        parts = _relative_path(path)
        start_line = _integer(request, "start_line", 1, 1, 10 * 1024 * 1024)
        max_lines = _integer(request, "max_lines", MAX_READ_LINES, 1, MAX_READ_LINES)
        fd = self._attachment_fd(request)
        try:
            text = self._text(self._read_file(fd, parts))
        finally:
            os.close(fd)
        selected: list[str] = []
        length = 0
        total_lines = 0
        full = False
        partial = False
        for number, line in enumerate(io.StringIO(text), 1):
            total_lines = number
            if number < start_line or len(selected) >= max_lines or full:
                continue
            length += len(line.encode("utf-8"))
            if length > MAX_CONTENT_BYTES:
                if not selected:
                    selected.append(line.encode("utf-8")[:MAX_CONTENT_BYTES].decode("utf-8", errors="ignore"))
                    partial = True
                full = True
            else:
                selected.append(line)
        end_line = start_line + len(selected) - 1
        return {
            "path": path, "start_line": start_line, "end_line": end_line, "content": "".join(selected),
            "total_lines": total_lines, "next_line": end_line + 1 if end_line < total_lines else None,
            **({"partial_line": True} if partial else {}),
        }

    def search(self, request: dict) -> dict:
        query = _string(request, "query", maximum=MAX_QUERY_CHARS)
        matches_pattern, pattern = _pattern(request)
        max_results = _integer(request, "max_results", MAX_SEARCH_RESULTS, 1, MAX_SEARCH_RESULTS)
        fd, base = self._scoped_fd(request)
        matches: list[dict] = []
        searched = skipped_binary = skipped_large = 0
        budget = [SEARCH_BYTE_BUDGET]
        walk = _Walk(fd, SEARCH_TIME_LIMIT, matches_pattern, pattern)
        message = None
        try:
            for path, size in walk.files(base):
                if size > MAX_FILE_BYTES:
                    skipped_large += 1
                    continue
                try:
                    content = self._read_file(fd, path.split("/"), budget)
                except HelperError as exc:
                    if exc.code == "limit":
                        skipped_large += 1
                    else:
                        walk.io_errors += 1
                    continue
                except OSError:
                    walk.io_errors += 1
                    continue
                try:
                    text = self._text(content)
                except HelperError:
                    skipped_binary += 1
                    continue
                searched += 1
                if query not in text:
                    continue
                for number, line in enumerate(io.StringIO(text), 1):
                    if number % 256 == 0:
                        walk.check_time()
                    if query not in line:
                        continue
                    if len(matches) == max_results:
                        raise _Exhausted("results")
                    snippet = line.rstrip("\r\n")[:MAX_SNIPPET_CHARS]
                    matches.append({"path": base + path, "line": number, "text": snippet})
        except _Exhausted as exc:
            message = _exhausted_message(str(exc), "search", walk)
        finally:
            os.close(fd)
        message = _walk_message(message, walk)
        result: dict[str, Any] = {
            "matches": matches, "truncated": message is not None, "searched_files": searched, "engine": walk.engine,
            "skipped_binary_files": skipped_binary, "skipped_large_files": skipped_large,
            "skipped_paths": walk.skipped_paths,
            "io_errors": walk.io_errors, "bytes_read": SEARCH_BYTE_BUDGET - budget[0],
            "visited_entries": walk.visited, "elapsed_seconds": round(walk.elapsed, 2),
        }
        if message:
            result["message"] = message
        return _fit_page(result, "matches")


# -- socket server ------------------------------------------------------------------------------

def _packet(response: dict) -> bytes:
    return json.dumps({"protocol": PROTOCOL_VERSION, **response}, ensure_ascii=True).encode("ascii") + b"\n"


def _fit_page(result: dict, key: str, offset: int = 0) -> dict:
    def fits(page: dict) -> bool:
        return len(_packet({"ok": True, "result": page})) <= MAX_RESPONSE_BYTES

    if fits(result):
        return result
    entries = result[key]
    reason = "Helper response limited to 512 KiB."
    page = {**result, "truncated": True, "message": " ".join(filter(None, (result.get("message"), reason)))}
    # At least one bounded entry fits. Find the largest complete prefix.
    lo, hi = 1, len(entries) - 1
    while lo < hi:
        n = (lo + hi + 1) // 2
        page[key] = entries[:n]
        if key == "files":
            page["next_offset"] = offset + n
        if fits(page):
            lo = n
        else:
            hi = n - 1
    page[key] = entries[:lo]
    if key == "files":
        page["next_offset"] = offset + lo
    return page


def _encode(response: dict) -> bytes:
    data = _packet(response)
    if len(data) > MAX_RESPONSE_BYTES:
        data = json.dumps({"protocol": PROTOCOL_VERSION, "ok": False, "code": "limit",
                           "error": "Helper response exceeds its size limit; "
                           "reduce limit, max_lines or max_results."}).encode("ascii") + b"\n"
    return data


def peer_allowed(connection: socket.socket) -> bool:
    """Accept only the helper's own user or root (the container root of a rootful engine)."""
    option = getattr(socket, "SO_PEERCRED", None)
    if option is None:
        return True
    credentials = connection.getsockopt(socket.SOL_SOCKET, option, struct.calcsize("3i"))
    _, uid, _ = struct.unpack("3i", credentials)
    return uid in (os.getuid(), 0)


class _Handler(socketserver.StreamRequestHandler):
    timeout = CONNECTION_TIMEOUT

    def handle(self) -> None:
        server: HelperServer = self.server  # type: ignore[assignment]
        try:
            line = self.rfile.readline(MAX_REQUEST_BYTES + 1)
        except OSError:
            return
        if len(line) > MAX_REQUEST_BYTES or not line.endswith(b"\n"):
            response = {"ok": False, "code": "invalid", "error": "Request is too large or incomplete."}
        else:
            try:
                request = json.loads(line.decode("utf-8"))
            except ValueError:
                response = {"ok": False, "code": "invalid", "error": "Request is not valid JSON."}
            else:
                response = server.helper.dispatch(request)
        try:
            self.wfile.write(_encode(response))
        except OSError:
            pass


def _short_path(path: str) -> tuple[str, int | None]:
    """A bindable/connectable path: long socket paths go through an open directory descriptor."""
    if len(os.fsencode(path)) < 100 or not os.path.isdir("/proc/self/fd"):
        return path, None
    directory, name = os.path.split(path)
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | _CLOEXEC)
    return f"/proc/self/fd/{fd}/{name}", fd


class HelperServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    request_queue_size = 32

    def service_actions(self) -> None:
        super().service_actions()
        self.helper.expire_pending_pins()

    def __init__(self, socket_path: str, helper: Helper):
        self.helper = helper
        self.socket_path = socket_path
        self.slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self.socket_name = os.path.basename(socket_path)
        self.directory_fd: int | None = None
        self.bound_socket: os.stat_result | None = None
        super().__init__(socket_path, _Handler, bind_and_activate=False)
        try:
            self.server_bind()
            self.server_activate()
        except BaseException:
            self.server_close()
            raise

    def server_bind(self) -> None:
        if self.socket_name in ("", ".", ".."):
            raise ValueError("Invalid socket name.")
        fd = prepare_socket_dir(os.path.dirname(self.socket_path))
        self.directory_fd = fd
        # AF_UNIX has no bindat(); fail closed if procfs is unavailable.
        address = f"/proc/self/fd/{fd}/{self.socket_name}"
        remove_stale_socket(fd, self.socket_name)
        previous = os.umask(0o177)
        try:
            self.socket.bind(address)
        finally:
            os.umask(previous)
        info = os.stat(self.socket_name, dir_fd=fd, follow_symlinks=False)
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError("Cannot verify private helper socket.")
        self.bound_socket = info

    def verify_request(self, request, client_address) -> bool:  # type: ignore[override]
        try:
            return peer_allowed(request)
        except OSError:
            return False

    def process_request(self, request, client_address) -> None:  # type: ignore[override]
        if not self.slots.acquire(blocking=False):
            try:
                request.sendall(_encode({"ok": False, "code": "busy", "error": "Helper is busy; retry shortly."}))
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address) -> None:  # type: ignore[override]
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def server_close(self) -> None:
        super().server_close()
        fd = self.directory_fd
        if fd is None:
            return
        self.directory_fd = None
        try:
            if self.bound_socket is not None:
                _unlink_socket(fd, self.socket_name, self.bound_socket)
        except OSError:
            pass
        finally:
            os.close(fd)


def prepare_socket_dir(directory: str) -> int:
    """Return a private socket directory fd; never follow links or chmod a pathname."""
    directory = os.path.abspath(directory)
    if not directory.strip("/"):
        raise ValueError("The socket requires a dedicated directory.")
    try:
        fd = _open_absolute(directory, create=True)
    except OSError as exc:
        if exc.errno in _LINK_ERRNOS:
            raise ValueError(f"Socket directory is not a directory or contains a symlink: {directory}") from exc
        raise
    try:
        if os.fstat(fd).st_uid != os.getuid():
            raise ValueError(f"Socket directory is owned by another user: {directory}")
        os.fchmod(fd, 0o700)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _unlink_socket(fd: int, name: str, expected: os.stat_result) -> None:
    current = os.stat(name, dir_fd=fd, follow_symlinks=False)
    if stat.S_ISSOCK(current.st_mode) and os.path.samestat(current, expected):
        os.unlink(name, dir_fd=fd)


def remove_stale_socket(fd: int, name: str) -> None:
    path_flag = getattr(os, "O_PATH", None)
    if path_flag is None:
        raise ValueError("Secure socket setup requires Linux O_PATH support.")
    try:
        entry = os.open(name, path_flag | os.O_NOFOLLOW | _CLOEXEC, dir_fd=fd)
    except FileNotFoundError:
        return
    try:
        info = os.fstat(entry)
        if not stat.S_ISSOCK(info.st_mode):
            raise ValueError(f"Refusing to replace a non-socket file: {name}")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
            probe.settimeout(2)
            try:
                probe.connect(f"/proc/self/fd/{entry}")
            except ConnectionRefusedError:
                _unlink_socket(fd, name, info)
                return
        raise ValueError(f"Another helper is already listening on {name}")
    finally:
        os.close(entry)


def request(socket_path: str, payload: dict, timeout: float = 40.0, max_bytes: int = MAX_RESPONSE_BYTES) -> dict:
    """Send one request and return the decoded reply (used by the wrapper and the backend)."""
    address, fd = _short_path(socket_path)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(timeout)
            connection.connect(address)
            connection.sendall(json.dumps(payload).encode("utf-8") + b"\n")
            chunks: list[bytes] = []
            size = 0
            while True:
                chunk = connection.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size > max_bytes:
                    raise ValueError("Helper reply exceeds its size limit.")
    finally:
        if fd is not None:
            os.close(fd)
    reply = json.loads(b"".join(chunks).decode("utf-8"))
    if not isinstance(reply, dict):
        raise ValueError("Helper reply is not a JSON object.")
    return reply


# -- process management -------------------------------------------------------------------------

_LOG_LOCK = threading.Lock()


def _log(message: str) -> None:
    with _LOG_LOCK:
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        print(f"{stamp} {message}", file=sys.stderr, flush=True)


def _daemonize(log_file: str) -> None:
    if os.fork() > 0:
        os._exit(0)
    os.setsid()
    if os.fork() > 0:
        os._exit(0)
    os.chdir("/")
    null = os.open(os.devnull, os.O_RDONLY)
    log = os.open(log_file, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    os.dup2(null, 0)
    os.dup2(log, 1)
    os.dup2(log, 2)
    os.close(null)
    os.close(log)


def _write_pid(pid_file: str) -> None:
    temporary = f"{pid_file}.tmp"
    with open(temporary, "w", encoding="ascii") as handle:
        handle.write(f"{os.getpid()}\n")
    os.chmod(temporary, 0o600)
    os.replace(temporary, pid_file)


def _serve(args: argparse.Namespace) -> int:
    if os.geteuid() == 0:
        print("Error: the host folder helper must not run as root; run it as the invoking user.", file=sys.stderr)
        return 1
    try:
        os.makedirs(args.state_dir, mode=0o700, exist_ok=True)
        os.chmod(args.state_dir, 0o700)
        helper = Helper(args.state_dir)
        server = HelperServer(os.path.abspath(args.socket), helper)
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    if args.daemon:
        _daemonize(args.log_file or os.devnull)
    if args.pid_file:
        _write_pid(args.pid_file)

    def stop(signum, frame):
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGHUP, stop)
    _log(f"host folder helper {os.getpid()} serving {args.socket}")
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        if args.pid_file:
            try:
                os.unlink(args.pid_file)
            except OSError:
                pass
        _log("host folder helper stopped")
    return 0


def _ping(args: argparse.Namespace) -> int:
    try:
        reply = request(args.socket, {"op": "status"}, timeout=5)
    except (OSError, ValueError) as exc:
        print(f"Helper is not responding on {args.socket}: {exc}", file=sys.stderr)
        return 1
    if not reply.get("ok"):
        print(f"Helper error: {reply.get('error')}", file=sys.stderr)
        return 1
    if reply.get("result", {}).get("protocol") != PROTOCOL_VERSION:
        print("Incompatible host folder helper; restart it with the current launcher.", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    if sys.version_info < MIN_PYTHON:
        print("Error: the host folder helper needs Python 3.9 or newer.", file=sys.stderr)
        return 1
    parser = argparse.ArgumentParser(description="VulnScout read-only host folder helper.")
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve", help="Serve attached folders on a private Unix socket.")
    serve.add_argument("--socket", required=True)
    serve.add_argument("--state-dir", required=True, help="Host-only directory holding the alias registry.")
    serve.add_argument("--daemon", action="store_true")
    serve.add_argument("--pid-file")
    serve.add_argument("--log-file")
    ping = commands.add_parser("ping", help="Check that a compatible host folder helper is running.")
    ping.add_argument("--socket", required=True)
    args = parser.parse_args(argv)
    if args.command == "serve":
        return _serve(args)
    return _ping(args)


if __name__ == "__main__":
    sys.exit(main())
