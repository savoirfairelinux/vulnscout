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
the helper resolves the alias to a host path from its own registry, re-checks that
path against the operator's approved roots (realpath containment), opens every path
component without following symbolic links, and bounds result counts, read sizes,
search time and bytes. No operation creates, changes or deletes anything under an
attached folder; the helper only writes its own registry file.
"""

from __future__ import annotations

import argparse
import errno
import io
import json
import os
import re
import signal
import socket
import socketserver
import stat
import struct
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from fnmatch import fnmatchcase, translate
from typing import Any, Callable, Iterator

PROTOCOL_VERSION = 1
SOCKET_NAME = "helper.sock"
REGISTRY_NAME = "registry.json"

MAX_REQUEST_BYTES = 64 * 1024
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
MAX_BROWSE_ENTRIES = 500
MAX_ATTACHMENTS_PER_VARIANT = 32
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
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | _CLOEXEC
_LINK_ERRNOS = (errno.ELOOP, errno.ENOTDIR)
_MOVED = "Attached folder was moved or replaced by a link; attach it again."


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


def _within(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


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
    return compile_pattern(pattern), _literal_prefix(pattern)


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


def _relative_path(path: str) -> list[str]:
    """Split a member path, rejecting traversal, absolute paths and excluded components."""
    if (not path or len(path) > 1024 or path.startswith("/") or "\\" in path
            or not _printable(path)):
        raise HelperError("invalid", "Path must be a relative path inside the attached folder.")
    parts = path.split("/")
    for part in parts:
        if part in ("", ".", ".."):
            raise HelperError("invalid", "Path must be a relative path inside the attached folder.")
        if _excluded(part):
            raise HelperError("not_found", "Source file not found or excluded.")
    return parts


def canonical_roots(paths: list[str], warn: Callable[[str], None] | None = None) -> list[str]:
    """Resolve approved roots; missing ones are skipped with a warning, unsafe ones rejected."""
    roots: list[str] = []
    for raw in paths:
        raw = raw.strip()
        if not raw:
            continue
        if not os.path.isabs(raw):
            raise ValueError(f"Approved root must be an absolute path: {raw}")
        real = os.path.realpath(raw)
        if real == "/":
            raise ValueError("The host root directory '/' cannot be an approved root.")
        if not os.path.isdir(real):
            if warn:
                warn(f"Skipping approved root that is not an existing directory: {raw}")
            continue
        if real not in roots:
            roots.append(real)
    return roots


def _open_under(root: str, path: str) -> int:
    """Open ``path`` (canonical, inside ``root``) as a directory without following any link."""
    relative = os.path.relpath(path, root)
    fd = os.open("/", _DIRECTORY_FLAGS)
    try:
        for part in root.split("/"):
            if not part:
                continue
            child = os.open(part, _DIRECTORY_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
        if relative != ".":
            for part in relative.split("/"):
                child = os.open(part, _DIRECTORY_FLAGS, dir_fd=fd)
                os.close(fd)
                fd = child
    except BaseException:
        os.close(fd)
        raise
    return fd


class Registry:
    """Alias -> host path, per variant, stored in a private host-only JSON file."""

    def __init__(self, state_dir: str):
        self.path = os.path.join(state_dir, REGISTRY_NAME)
        self.lock = threading.Lock()
        self.data: dict[str, dict[str, dict[str, str]]] = {}
        try:
            with open(self.path, encoding="utf-8") as handle:
                loaded = json.load(handle)
            attachments = loaded.get("attachments") if isinstance(loaded, dict) else None
            if isinstance(attachments, dict):
                for variant_id, aliases in attachments.items():
                    if not isinstance(aliases, dict):
                        continue
                    self.data[variant_id] = {
                        alias: entry for alias, entry in aliases.items()
                        if ALIAS_RE.fullmatch(alias) and isinstance(entry, dict)
                        and isinstance(entry.get("path"), str)
                    }
        except FileNotFoundError:
            pass
        except (OSError, ValueError) as exc:
            raise ValueError(f"Cannot read helper registry {self.path}: {exc}") from exc

    def get(self, variant_id: str, alias: str) -> str | None:
        with self.lock:
            entry = self.data.get(variant_id, {}).get(alias)
            return entry["path"] if entry else None

    def aliases(self, variant_id: str) -> dict[str, str]:
        with self.lock:
            return {alias: entry["path"] for alias, entry in self.data.get(variant_id, {}).items()}

    def set(self, variant_id: str, alias: str, path: str) -> None:
        with self.lock:
            aliases = self.data.setdefault(variant_id, {})
            if alias not in aliases and len(aliases) >= MAX_ATTACHMENTS_PER_VARIANT:
                raise HelperError(
                    "limit", f"A variant can have at most {MAX_ATTACHMENTS_PER_VARIANT} attached folders.")
            if aliases.get(alias, {}).get("path") == path:
                return
            aliases[alias] = {"path": path, "created_at": datetime.now(timezone.utc).isoformat()}
            self._save()

    def remove(self, variant_id: str, alias: str) -> bool:
        with self.lock:
            aliases = self.data.get(variant_id, {})
            if alias not in aliases:
                return False
            del aliases[alias]
            if not aliases:
                self.data.pop(variant_id, None)
            self._save()
            return True

    def _save(self) -> None:
        temporary = f"{self.path}.{os.getpid()}.{threading.get_ident()}.tmp"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _CLOEXEC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump({"version": PROTOCOL_VERSION, "attachments": self.data}, handle, indent=2, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
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
                 literal: str = ""):
        self.root_fd = root_fd
        self.started = time.monotonic()
        self.deadline = self.started + time_limit
        self.visited = 0
        self.matcher = matcher
        self.literal = literal

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.started

    def files(self) -> Iterator[tuple[str, int]]:
        yield from self._walk(self.root_fd, "")

    def _may_contain(self, directory: str) -> bool:
        return self.literal.startswith(directory) or directory.startswith(self.literal)

    def _walk(self, directory_fd: int, prefix: str) -> Iterator[tuple[str, int]]:
        try:
            with os.scandir(directory_fd) as iterator:
                entries = []
                for entry in iterator:
                    self._tick()
                    entries.append(entry)
        except PermissionError:
            return
        entries.sort(key=lambda item: item.name)
        for entry in entries:
            if time.monotonic() > self.deadline:
                raise _Exhausted("time")
            if _excluded(entry.name) or not _printable(entry.name):
                continue
            try:
                is_dir = entry.is_dir(follow_symlinks=False)
                is_file = not is_dir and entry.is_file(follow_symlinks=False)
            except OSError:
                continue
            if is_dir:
                directory = f"{prefix}{entry.name}/"
                if not self._may_contain(directory):
                    continue
                try:
                    child = os.open(entry.name, _DIRECTORY_FLAGS, dir_fd=directory_fd)
                except OSError:
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
                    continue

    def _tick(self) -> None:
        self.visited += 1
        if self.visited > MAX_WALK_ENTRIES:
            raise _Exhausted("entries")
        if self.visited % 256 == 0 and time.monotonic() > self.deadline:
            raise _Exhausted("time")


def _exhausted_message(reason: str, operation: str, walk: "_Walk | None" = None) -> str:
    detail = f" (visited {walk.visited} entries in {walk.elapsed:.1f}s)" if walk else ""
    advice = ("narrow the pattern with a literal folder prefix such as 'build/tmp/work/*/curl/*' "
              "or attach a smaller folder.")
    if reason == "entries":
        return f"The {operation} stopped after visiting {MAX_WALK_ENTRIES} entries{detail}; {advice}"
    if reason == "bytes":
        mebibytes = SEARCH_BYTE_BUDGET // (1024 * 1024)
        return f"The {operation} stopped after reading {mebibytes} MiB{detail}; narrow the pattern."
    return f"The {operation} stopped at its time limit{detail}; {advice}"


class Helper:
    """Request dispatcher; holds the approved roots and the registry."""

    def __init__(self, roots: list[str], state_dir: str):
        self.roots = list(roots)
        self.registry = Registry(state_dir)
        self.operations: dict[str, Callable[[dict], dict]] = {
            "status": self.status, "browse": self.browse, "attach": self.attach, "detach": self.detach,
            "sync": self.sync, "source": self.source,
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

    def root_for(self, path: str) -> str | None:
        matches = [root for root in self.roots if _within(path, root)]
        return max(matches, key=len) if matches else None

    def _approved(self, path: str) -> tuple[str, str]:
        """(canonical path, root) for an absolute host path inside an approved root."""
        if not os.path.isabs(path):
            raise HelperError("invalid", "Host path must be absolute.")
        real = os.path.realpath(path)
        root = self.root_for(real)
        if root is None:
            raise HelperError("forbidden", "Host path is outside the operator-approved roots.")
        relative = os.path.relpath(real, root)
        if relative != "." and any(_excluded(part) for part in relative.split("/")):
            raise HelperError("forbidden", "Hidden or sensitive folders cannot be browsed or attached.")
        return real, root

    def _open_folder(self, path: str, root: str) -> int:
        try:
            return _open_under(root, path)
        except FileNotFoundError:
            raise HelperError("not_found", "Host folder not found.") from None
        except PermissionError:
            raise HelperError("unavailable", "Host folder is not readable by the helper user.") from None
        except OSError as exc:
            if exc.errno in _LINK_ERRNOS:
                raise HelperError("invalid", "Host path is not a directory or changed while it was opened.") from None
            raise HelperError("unavailable", "Host folder cannot be opened.") from None

    def _attachment_fd(self, request: dict) -> int:
        authorized_path = request.get("authorized_path")
        if authorized_path is not None:
            authorized_folder = _string({"path": authorized_path}, "path")
            real, root = self._checked(authorized_folder)
            return self._open_folder(real, root)
        variant_id = _variant_id(request)
        alias = validate_alias(request.get("alias"))
        path = self.registry.get(variant_id, alias)
        if path is None:
            raise HelperError("not_found", f"No folder is attached as '{alias}' for this variant.")
        real, root = self._checked(path)
        return self._open_folder(real, root)

    def _checked(self, path: str) -> tuple[str, str]:
        real, root = self._approved(path)
        if real != path:
            raise HelperError("unavailable", _MOVED)
        return real, root

    # -- operations ---------------------------------------------------------------------------

    def status(self, request: dict) -> dict:
        return {"protocol": PROTOCOL_VERSION, "roots": list(self.roots), "read_only": True}

    def browse(self, request: dict) -> dict:
        path = _string(request, "path", required=False)
        if not path:
            return {"path": None, "root": None, "parent": None, "truncated": False,
                    "directories": [{"name": root, "path": root} for root in self.roots]}
        real, root = self._approved(path)
        fd = self._open_folder(real, root)
        names: list[str] = []
        truncated = False
        try:
            with os.scandir(fd) as iterator:
                for count, entry in enumerate(iterator, 1):
                    if count > MAX_WALK_ENTRIES:
                        truncated = True
                        break
                    if _excluded(entry.name) or not _printable(entry.name):
                        continue
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            names.append(entry.name)
                    except OSError:
                        continue
        finally:
            os.close(fd)
        names.sort()
        if len(names) > MAX_BROWSE_ENTRIES:
            names, truncated = names[:MAX_BROWSE_ENTRIES], True
        return {
            "path": real, "root": root, "parent": os.path.dirname(real) if real != root else None,
            "truncated": truncated,
            "directories": [{"name": name, "path": os.path.join(real, name)} for name in names],
        }

    def _validated_folder(self, path: str) -> str:
        real, root = self._approved(path)
        os.close(self._open_folder(real, root))
        return real

    def attach(self, request: dict) -> dict:
        variant_id = _variant_id(request)
        alias = validate_alias(request.get("alias"))
        path = _string(request, "path")
        real = self._validated_folder(path)
        if request.get("exact") is True and real != path:
            # Re-registration of a stored attachment must not silently follow a replaced folder.
            raise HelperError("unavailable", _MOVED)
        self.registry.set(variant_id, alias, real)
        return {"variant_id": variant_id, "alias": alias, "path": real}

    def detach(self, request: dict) -> dict:
        variant_id = _variant_id(request)
        alias = validate_alias(request.get("alias"))
        return {"removed": self.registry.remove(variant_id, alias)}

    def source(self, request: dict) -> dict:
        """Browse a database-authorized mount path without resolving its mutable alias again."""
        _variant_id(request)
        validate_alias(request.get("alias"))
        path = _string(request, "mount_path")
        operation = request.get("source_operation")
        if operation not in ("list", "read", "search"):
            raise HelperError("invalid", "Operation must be list, read, or search.")
        forwarded = {**request, "authorized_path": path}
        return {
            "list": self.list_files,
            "read": self.read,
            "search": self.search,
        }[operation](forwarded)

    def sync(self, request: dict) -> dict:
        """Align a variant's registry with the backend's attachments and report availability."""
        variant_id = _variant_id(request)
        wanted = request.get("attachments")
        if not isinstance(wanted, dict) or len(wanted) > MAX_ATTACHMENTS_PER_VARIANT:
            raise HelperError("invalid", "attachments must map at most "
                              f"{MAX_ATTACHMENTS_PER_VARIANT} aliases to host paths.")
        for alias in self.registry.aliases(variant_id):
            if alias not in wanted:
                self.registry.remove(variant_id, alias)
        report: dict[str, dict[str, Any]] = {}
        for alias, path in wanted.items():
            validate_alias(alias)
            if not isinstance(path, str) or not path or len(path) > MAX_PATH_CHARS:
                raise HelperError("invalid", "Each attachment needs a host path.")
            try:
                real = self._validated_folder(path)
                if real != path:
                    raise HelperError("unavailable", _MOVED)
                self.registry.set(variant_id, alias, real)
                report[alias] = {"status": "available", "message": "Folder is available read-only."}
            except HelperError as exc:
                report[alias] = {"status": "unavailable", "message": exc.message}
        return {"attachments": report}

    def list_files(self, request: dict) -> dict:
        matches_pattern, literal = _pattern(request)
        offset = _integer(request, "offset", 0, 0, MAX_WALK_ENTRIES)
        limit = _integer(request, "limit", MAX_LIST_LIMIT, 1, MAX_LIST_LIMIT)
        fd = self._attachment_fd(request)
        walk = _Walk(fd, LIST_TIME_LIMIT, matches_pattern, literal)
        files: list[dict] = []
        total = 0
        message = None
        try:
            for path, size in walk.files():
                if offset <= total < offset + limit:
                    files.append({"path": path, "size": size})
                total += 1
        except _Exhausted as exc:
            message = _exhausted_message(str(exc), "listing", walk)
        finally:
            os.close(fd)
        result: dict[str, Any] = {
            "files": files, "total": total, "truncated": message is not None,
            "visited_entries": walk.visited, "elapsed_seconds": round(walk.elapsed, 2),
            "next_offset": offset + limit if offset + limit < total else None,
        }
        if message:
            result["message"] = message
        return result

    def _read_file(self, root_fd: int, parts: list[str], budget: list[int] | None = None) -> bytes:
        directory_fd = root_fd
        opened: list[int] = []
        try:
            for part in parts[:-1]:
                directory_fd = os.open(part, _DIRECTORY_FLAGS, dir_fd=directory_fd)
                opened.append(directory_fd)
            fd = os.open(parts[-1], _FILE_FLAGS, dir_fd=directory_fd)
        except FileNotFoundError:
            raise HelperError("not_found", "Source file not found or excluded.") from None
        except OSError as exc:
            if exc.errno in _LINK_ERRNOS:
                raise HelperError("invalid", "Links and special files cannot be read.") from None
            raise HelperError("unavailable", "Source file cannot be opened.") from None
        finally:
            for item in opened:
                os.close(item)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            os.close(fd)
            raise HelperError("invalid", "Directories, links and special files cannot be read.")
        with io.FileIO(fd) as source:
            if info.st_size > MAX_FILE_BYTES:
                raise HelperError("limit", "Source file exceeds the maximum readable file size of 10 MiB.")
            if budget is not None and info.st_size > budget[0]:
                raise _Exhausted("bytes")
            content = source.read(MAX_FILE_BYTES + 1)
        if len(content) > MAX_FILE_BYTES:
            raise HelperError("limit", "Source file exceeds the maximum readable file size of 10 MiB.")
        if budget is not None:
            budget[0] -= len(content)
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
        for number, line in enumerate(io.StringIO(text), 1):
            total_lines = number
            if number < start_line or len(selected) >= max_lines or full:
                continue
            length += len(line.encode("utf-8"))
            if length > MAX_CONTENT_BYTES:
                if not selected:
                    raise HelperError("limit", "Source line exceeds the maximum response size of 64 KiB.")
                full = True
            else:
                selected.append(line)
        end_line = start_line + len(selected) - 1
        return {
            "path": path, "start_line": start_line, "end_line": end_line, "content": "".join(selected),
            "total_lines": total_lines, "next_line": end_line + 1 if end_line < total_lines else None,
        }

    def search(self, request: dict) -> dict:
        query = _string(request, "query", maximum=MAX_QUERY_CHARS)
        matches_pattern, literal = _pattern(request)
        max_results = _integer(request, "max_results", MAX_SEARCH_RESULTS, 1, MAX_SEARCH_RESULTS)
        needle = query.encode("utf-8")
        fd = self._attachment_fd(request)
        matches: list[dict] = []
        searched = skipped_binary = skipped_large = 0
        budget = [SEARCH_BYTE_BUDGET]
        walk = _Walk(fd, SEARCH_TIME_LIMIT, matches_pattern, literal)
        truncated = False
        message = None
        try:
            for path, size in walk.files():
                if size > MAX_FILE_BYTES:
                    skipped_large += 1
                    continue
                try:
                    content = self._read_file(fd, path.split("/"), budget)
                except HelperError as exc:
                    if exc.code == "limit":
                        skipped_large += 1
                    else:
                        skipped_binary += 1
                    continue
                if b"\x00" in content:
                    skipped_binary += 1
                    continue
                if needle not in content:
                    searched += 1
                    continue
                try:
                    text = self._text(content)
                except HelperError:
                    skipped_binary += 1
                    continue
                searched += 1
                for number, line in enumerate(io.StringIO(text), 1):
                    if query not in line:
                        continue
                    if len(matches) == max_results:
                        raise _Exhausted("results")
                    matches.append({"path": path, "line": number, "text": line.rstrip("\r\n")[:MAX_SNIPPET_CHARS]})
        except _Exhausted as exc:
            truncated = True
            if str(exc) != "results":
                message = _exhausted_message(str(exc), "search", walk)
        finally:
            os.close(fd)
        result: dict[str, Any] = {
            "matches": matches, "truncated": truncated, "searched_files": searched,
            "skipped_binary_files": skipped_binary, "skipped_large_files": skipped_large,
            "visited_entries": walk.visited, "elapsed_seconds": round(walk.elapsed, 2),
        }
        if message:
            result["message"] = message
        return result


# -- socket server ------------------------------------------------------------------------------

def _encode(response: dict) -> bytes:
    data = json.dumps(response, ensure_ascii=True).encode("ascii") + b"\n"
    if len(data) > MAX_RESPONSE_BYTES:
        data = json.dumps({"ok": False, "code": "limit", "error": "Helper response exceeds its size limit; "
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

    def __init__(self, socket_path: str, helper: Helper):
        self.helper = helper
        self.socket_path = socket_path
        self.slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self.bound = False
        super().__init__(socket_path, _Handler, bind_and_activate=False)
        try:
            self.server_bind()
            self.server_activate()
        except BaseException:
            self.server_close()
            raise

    def server_bind(self) -> None:
        prepare_socket_dir(os.path.dirname(self.socket_path))
        remove_stale_socket(self.socket_path)
        address, fd = _short_path(self.socket_path)
        previous = os.umask(0o177)
        try:
            self.socket.bind(address)
        finally:
            os.umask(previous)
            if fd is not None:
                os.close(fd)
        self.bound = True
        os.chmod(self.socket_path, 0o600)

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
        if not self.bound:
            return
        self.bound = False
        try:
            if stat.S_ISSOCK(os.lstat(self.socket_path).st_mode):
                os.unlink(self.socket_path)
        except OSError:
            pass


def prepare_socket_dir(directory: str) -> None:
    """Create the private socket directory, refusing links and foreign or shared directories."""
    os.makedirs(directory, mode=0o700, exist_ok=True)
    info = os.lstat(directory)
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError(f"Socket directory is not a directory: {directory}")
    if info.st_uid != os.getuid():
        raise ValueError(f"Socket directory is owned by another user: {directory}")
    os.chmod(directory, 0o700)


def remove_stale_socket(path: str) -> None:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(info.st_mode):
        raise ValueError(f"Refusing to replace a non-socket file: {path}")
    try:
        request(path, {"op": "status"}, timeout=2)
    except (OSError, ValueError):
        os.unlink(path)
        return
    raise ValueError(f"Another helper is already listening on {path}")


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
        roots = canonical_roots(args.root, warn=lambda text: print(f"Warning: {text}", file=sys.stderr))
        if not roots:
            raise ValueError("No approved host root exists; set VULNSCOUT_HOST_ROOTS to existing folders.")
        os.makedirs(args.state_dir, mode=0o700, exist_ok=True)
        os.chmod(args.state_dir, 0o700)
        helper = Helper(roots, args.state_dir)
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
    _log(f"host folder helper {os.getpid()} serving {args.socket} for roots: {', '.join(roots)}")
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
    for root in reply["result"].get("roots", []):
        print(root)
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
    serve.add_argument("--root", action="append", default=[], help="Approved host root (repeatable).")
    serve.add_argument("--daemon", action="store_true")
    serve.add_argument("--pid-file")
    serve.add_argument("--log-file")
    ping = commands.add_parser("ping", help="Print the approved roots of a running helper.")
    ping.add_argument("--socket", required=True)
    args = parser.parse_args(argv)
    if args.command == "serve":
        return _serve(args)
    return _ping(args)


if __name__ == "__main__":
    sys.exit(main())
