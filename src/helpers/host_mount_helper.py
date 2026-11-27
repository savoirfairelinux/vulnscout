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
component without following symbolic links, and bounds result counts and read sizes.
No operation creates, changes or deletes anything under an
attached folder; the helper only writes its own registry file.
"""

from __future__ import annotations

import argparse
import base64
import codecs
import ctypes
import errno
import fcntl
import hashlib
import hmac
import io
import json
import os
import re
import selectors
import shutil
import signal
import socket
import socketserver
import sqlite3
import stat
import struct
import subprocess
import sys
import threading
import time
import uuid
import weakref
from contextlib import ExitStack, closing, contextmanager
from datetime import datetime, timezone
from fnmatch import fnmatchcase, translate
from typing import Any, Callable, ContextManager, Iterator

PROTOCOL_VERSION = 4
SOCKET_NAME = "helper.sock"
REGISTRY_NAME = "registry.json"

MAX_RESPONSE_BYTES = 512 * 1024
MAX_CONTENT_BYTES = 64 * 1024
MAX_FILE_BYTES = 10 * 1024 * 1024
SEARCH_BYTES = 1024 * 1024
SEARCH_CHUNK = 32 * 1024
SEARCH_MATCHES = 100
SEARCH_SECONDS = 1.0
POSITION_RADIUS = 4096
POSITION_LINES = 21
_CURSOR_KEY = os.urandom(32)
MAX_WALK_ENTRIES = 500_000
LIST_TIME_LIMIT = 10.0
SEARCH_TIME_LIMIT = 20.0
SEARCH_BYTE_BUDGET = 100 * 1024 * 1024
MAX_LIST_LIMIT = 200
MAX_CHILD_RECORDS = 256
MAX_READ_LINES = 200
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
SHELL_TIMEOUT = 15.0
SHELL_DRAIN_TIMEOUT = 20.0
_LEASE_NAME = ".lease"
_PROXY_LOWER = ("http_proxy", "https_proxy", "ftp_proxy", "all_proxy", "no_proxy")
_PROXY_VARIABLES = _PROXY_LOWER + tuple(name.upper() for name in _PROXY_LOWER)
SHELL_OUTPUT_BYTES = 64 * 1024
DEFAULT_SNAPSHOT_MIB = 512
SNAPSHOT_CHUNK = 256 * 1024
DIRECT_READ_LIMIT_MESSAGE = (
    "Direct read exceeds the maximum readable file size of 10 MiB; use search_codebase_file for a known log."
)

ALIAS_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,31}")
ALIAS_RULE = "Alias must be 1-32 lowercase letters, digits, '_' or '-', starting with a letter or digit."

_SENSITIVE_NAMES = (
    "*secret*", "*credential*", "*password*", "*token*", "*.pem", "*.key", "*.p12", "*.pfx",
    "*.keystore", "id_rsa*", "id_ed25519*", "id_dsa*", "id_ecdsa*", "kubeconfig",
    "*.kdbx", "*.sqlite*", "*.db", "*~", "*.bak",
)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | _CLOEXEC
_LINK_ERRNOS = (errno.ELOOP, errno.ENOTDIR)
_MOVED = "Attached folder or its mount was moved or replaced. Attach it again."
_UNVERIFIED = "Cannot verify the previously approved folder. Check the host path and reattach with the host CLI."
_LEGACY = "Earlier approval cannot distinguish reboot from replacement. Check the path and reattach with the host CLI."
_REBOOT = "Approval cannot be verified after host reboot; check the host path and reattach with the host CLI."
_IDENTITY = r"(?:h[0-9a-f]{64}|s[0-9a-f]{32}|b[0-9a-f]{32}\.[0-9a-f]{64}|d[0-9a-f]{32}(?:\.[0-9a-f]{64}){2})"


class HelperError(Exception):
    """A request failed; ``code`` is one of invalid, forbidden, not_found, unavailable, limit, busy, internal."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class _Exhausted(Exception):
    """A walk exceeded its entry or time budget."""


def _excluded(name: str, *, file_candidate: bool = False) -> bool:
    if file_candidate and name == ".config":
        return False  # The caller must verify a single-link regular file, never a directory.
    return name.startswith(".") or any(fnmatchcase(name.lower(), pattern) for pattern in _SENSITIVE_NAMES)


def _excluded_config(name: str, info: os.stat_result) -> bool:
    return name == ".config" and not (stat.S_ISREG(info.st_mode) and info.st_nlink == 1)


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
    """Optional sub-folder of the attachment that scopes a list or snapshot."""
    folder = _string(request, "folder", required=False, maximum=1024)
    return _relative_path(folder.rstrip("/"), folder=True) if folder else []


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


def _relative_path(path: str, *, folder: bool = False) -> list[str]:
    """Split a member path, rejecting traversal, absolute paths and excluded components."""
    if not path or not _member_path_fits(path) or path.startswith("/"):
        raise HelperError("invalid", "Path must be a relative path inside the attached folder.")
    parts = path.split("/")
    for index, part in enumerate(parts):
        if part in ("", ".", ".."):
            raise HelperError("invalid", "Path must be a relative path inside the attached folder.")
        if _excluded(part, file_candidate=not folder and index == len(parts) - 1):
            raise HelperError("not_found", "Source file not found or excluded.")
    return parts


def _signed_cursor(binding: bytes, position: str) -> str:
    return position + "." + hmac.digest(_CURSOR_KEY, binding + b":" + position.encode(), "sha256").hex()


def _file_version(fd: int) -> tuple[int, ...]:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise HelperError("invalid", "Expected a regular file without links.")
    return info.st_dev, info.st_ino, info.st_ctime_ns, info.st_mtime_ns, info.st_size


def _position_binding(scope: str, path: str, version: tuple[int, ...]) -> bytes:
    return json.dumps(["read-position-v1", scope, path, version]).encode()


def _position_token(binding: bytes, offset: int, line: int) -> str:
    data = struct.pack("!QQ", offset, line)
    return base64.urlsafe_b64encode(data + hmac.digest(_CURSOR_KEY, binding + data, "sha256")).decode("ascii")


def read_position(open_current: Callable[[], ContextManager[int]], scope: str, path: str,
                  position: str, max_lines: int) -> dict:
    if not re.fullmatch(r"[A-Za-z0-9_-]{64}", position):
        raise HelperError("invalid", "Invalid read position; search this file again.")
    offset, line = struct.unpack("!QQ", base64.urlsafe_b64decode(position)[:16])
    with open_current() as fd:
        version = _file_version(fd)
        binding = _position_binding(scope, path, version)
        if not hmac.compare_digest(position, _position_token(binding, offset, line)):
            raise HelperError("invalid", "Invalid or stale read position; search this file again.")
        result = _position_window(fd, path, version[-1], offset, line, max_lines)
        if _file_version(fd) != version:
            raise HelperError("unavailable", "File changed during positioned read; search again.")
        # An ancestor may have been replaced or the mount revoked without changing the pinned inode.
        with open_current() as current:
            if _file_version(current) != version:
                raise HelperError("unavailable", "Source changed during positioned read; search again.")
    return result


def _position_window(fd: int, path: str, size: int, offset: int, line: int, max_lines: int) -> dict:
    start = max(0, offset - POSITION_RADIUS)
    end = min(size, offset + POSITION_RADIUS)
    # One guard byte distinguishes a clipped line from a window starting just after LF.
    guard = int(start > 0)
    block = os.pread(fd, end - start + guard, start - guard)
    if len(block) != end - start + guard:
        raise HelperError("unavailable", "Incomplete positioned read; search this file again.")
    if b"\0" in block:
        raise HelperError("invalid", "Positioned read encountered binary content.")
    cut = guard + offset - start
    left, right = block[guard:cut], block[cut:]
    partial_first = bool(guard and not block.startswith(b"\n"))
    if guard:
        # Drop only continuation bytes of a UTF-8 character cut by the left byte boundary.
        for _ in range(3):
            if not left or left[0] & 0xC0 != 0x80:
                break
            left = left[1:]
    try:
        before = left.decode("utf-8").split("\n")
        after, _ = codecs.utf_8_decode(right, "strict", end == size)
    except UnicodeDecodeError as exc:
        raise HelperError("invalid", "Positioned read encountered invalid UTF-8.") from exc
    limit = min(max_lines, POSITION_LINES)
    preceding = min((limit - 1) // 2, len(before) - 1)
    dropped = preceding < len(before) - 1
    prefix = "\n".join(before[-(preceding + 1):])
    # Split only at LF, the same delimiter used by search to sign the match line.
    tail = after.split("\n", limit - preceding)
    suffix = "\n".join(tail) if len(tail) <= limit - preceding else "\n".join(tail[:-1]) + "\n"
    content = prefix + suffix
    truncated_after = end < size or len(suffix) < len(after)
    result = {"path": path, "content": content, "match_line": line, "start_line": line - preceding,
              "end_line": line + suffix.count("\n") - int(suffix.endswith("\n")),
              "truncated_before": bool(start or dropped), "truncated_after": truncated_after,
              "partial_first_line": partial_first and not dropped,
              "partial_last_line": truncated_after and not suffix.endswith("\n")}
    if len(json.dumps(result)) > MAX_CONTENT_BYTES - 1024:
        raise HelperError("limit", "Positioned read exceeds the serialized response limit.")
    return result


def search_file_page(fd: int, scope: str, request: dict) -> dict:
    """Scan a pinned regular file. Offsets identify the first untested character, not the read head."""
    path = _string(request, "path", maximum=1024)
    query = _string(request, "query", maximum=200)
    if "\n" in query or "\r" in query or not _printable(query.replace("\t", "")):
        raise HelperError("invalid", "Search query must be a single-line UTF-8 literal.")
    cursor = _string(request, "cursor", required=False, maximum=160)

    version = _file_version(fd)
    size = version[-1]
    binding = json.dumps([scope, path, query, version]).encode()
    position_binding = _position_binding(scope, path, version)

    offset, line, left_word = 0, 1, False
    if cursor:
        fields = re.fullmatch(r"(\d{1,20}):(\d{1,20}):([01])\.[0-9a-f]{64}", cursor, re.ASCII)
        if not fields or not hmac.compare_digest(cursor, _signed_cursor(binding, cursor.split(".")[0])):
            raise HelperError("invalid", "Search cursor is invalid or the file changed; restart this search.")
        offset, line = int(fields[1]), int(fields[2])
        left_word = fields[3] == "1"

    literal = re.escape(query)
    if re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", query, re.I):
        literal = r"(?<!\w)" + literal + r"(?!\w)"
    pattern = re.compile(literal)
    deadline = time.monotonic() + SEARCH_SECONDS
    scanned = wire = 0
    matches: list[dict] = []
    complete = False
    while scanned + SEARCH_CHUNK <= SEARCH_BYTES:
        block = os.pread(fd, SEARCH_CHUNK, offset)
        scanned += len(block)
        if len(block) != min(SEARCH_CHUNK, size - offset):
            raise HelperError("unavailable", "File size changed or cannot be verified.")
        eof = offset + len(block) == size
        if b"\0" in block:
            raise HelperError("invalid", "Source file is binary; only UTF-8 text can be searched.")
        try:
            decoded, _ = codecs.utf_8_decode(block, "strict", eof)
        except UnicodeDecodeError as exc:
            raise HelperError("invalid", "Source file is not UTF-8 text.") from exc
        # Carry left word context and leave enough lookahead for a whole query and its right boundary.
        text = ("a" if left_word else " ") + decoded
        end = len(text) if eof else len(text) - len(query)
        pos = 1
        byte_pos = offset
        while pos < end:
            hit = pattern.search(text, pos)
            stop = hit.start() if hit and hit.start() < end else end
            line += text.count("\n", pos, stop)
            byte_pos += len(text[pos:stop].encode())
            pos = stop
            if pos == end:
                break
            assert hit is not None
            before = text[max(1, pos - 60):pos].rsplit("\n", 1)[-1]
            after = text[hit.end():hit.end() + 60].split("\n", 1)[0]
            row = {"path": path, "line": line, "text": before + query + after,
                   "position": _position_token(position_binding, byte_pos, line)}
            # Also allow separators and indentation when Flask pretty-prints the envelope.
            cost = len(json.dumps(row, ensure_ascii=True)) + 48
            if wire + cost > MAX_CONTENT_BYTES - 1024:  # Reserve the response envelope and cursor.
                break
            matches.append(row)
            wire += cost
            byte_pos += len(text[pos].encode())
            pos += 1  # Also find overlapping literal occurrences.
            if len(matches) == SEARCH_MATCHES or time.monotonic() >= deadline:
                break
        offset = byte_pos
        left_word = text[pos - 1].isalnum() or text[pos - 1] == "_"
        complete = eof and pos == len(text)
        if complete or pos < end or len(matches) == SEARCH_MATCHES or time.monotonic() >= deadline:
            break
    if _file_version(fd) != version:
        raise HelperError("unavailable", "Source changed during search; restart this search.")
    return {"matches": matches, "bytes_scanned": scanned, "complete": complete,
            "next_cursor": None if complete else _signed_cursor(binding, f"{offset}:{line}:{int(left_word)}")}


def _directory_records(fd: int, cookie: int) -> Iterator[tuple[int, str]]:
    """Read Linux dirent64 records in fixed-size batches; d_off resumes without replay."""
    # The standalone Linux helper cannot import application dependencies. scandir()
    # hides the per-entry filesystem cookie and its buffered descriptor offset
    # can already point past entries the caller has not consumed.
    os.lseek(fd, cookie, os.SEEK_SET)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.fdopendir.argtypes = (ctypes.c_int,)
    libc.fdopendir.restype = ctypes.c_void_p
    libc.closedir.argtypes = (ctypes.c_void_p,)
    # musl uses the 64-bit layout for readdir; glibc also exports readdir64.
    read = getattr(libc, "readdir64", libc.readdir)
    read.argtypes = (ctypes.c_void_p,)
    read.restype = ctypes.c_void_p
    duplicate = os.dup(fd)
    stream = libc.fdopendir(duplicate)
    if not stream:
        os.close(duplicate)
        raise OSError(ctypes.get_errno(), "Cannot open directory stream.")
    header = struct.Struct("=QqHB")
    try:
        while True:
            ctypes.set_errno(0)
            entry = read(stream)
            if not entry:
                if ctypes.get_errno():
                    raise OSError(ctypes.get_errno(), "Cannot enumerate directory.")
                return
            _, after, length, _ = header.unpack(ctypes.string_at(entry, header.size))
            if length <= header.size:
                raise OSError("Invalid directory record.")
            name = ctypes.string_at(entry + header.size, length - header.size).split(b"\0", 1)[0]
            yield after, os.fsdecode(name)
    finally:
        libc.closedir(stream)


def children_page(fd: int, base: str, request: dict, scope: str) -> dict:
    limit = _integer(request, "limit", 50, 1, MAX_LIST_LIMIT)
    cursor = _string(request, "cursor", required=False, maximum=100)

    def directory_version() -> tuple[int, ...]:
        info = os.fstat(fd)
        return info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns

    version = directory_version()
    binding = json.dumps(["children", scope, base, version]).encode()
    cookie = 0
    if cursor:
        match = re.fullmatch(r"([0-9a-f]{1,16})\.[0-9a-f]{64}", cursor)
        if not match or not hmac.compare_digest(cursor, _signed_cursor(binding, match[1])):
            raise HelperError("invalid", "Invalid or stale cursor; restart this folder listing.")
        cookie = int(match[1], 16)
    children: list[dict] = []
    visited = size = 0
    complete = filtered = False
    for records, (after, name) in enumerate(_directory_records(fd, cookie), 1):
        path = base + name
        real = name not in (".", "..")
        visited += int(real)
        if real and not _excluded(name, file_candidate=True) and _member_path_fits(path):
            try:
                item = os.stat(name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError as exc:
                raise HelperError("invalid", "Directory changed; restart this folder listing.") from exc
            if ((stat.S_ISDIR(item.st_mode) and not _excluded_config(name, item))
                    or (stat.S_ISREG(item.st_mode) and item.st_nlink == 1)):
                child = {"path": path, "type": "directory" if stat.S_ISDIR(item.st_mode) else "file"}
                cost = len(json.dumps(child)) + 2
                if size + cost > MAX_CONTENT_BYTES - 1024:
                    break  # Resume before this entry.
                children.append(child)
                size += cost
            else:
                filtered = True
        elif real:
            filtered = True
        cookie = after
        if len(children) == limit or records >= MAX_CHILD_RECORDS:
            break
    else:
        complete = True
    if directory_version() != version:
        raise HelperError("invalid", "Directory changed; restart this folder listing.")
    return {"children": children, "complete": complete, "visited_entries": visited, "entries_filtered": filtered,
            "next_cursor": None if complete else _signed_cursor(binding, f"{cookie:x}")}


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


def _file_handle(fd: int) -> tuple[int, bytes] | None:
    """Read the unique mount ID and typed export handle from the already-open object."""
    if _NAME_TO_HANDLE_AT is None:
        return None
    handle = _FileHandle()
    handle.size = len(handle.data)
    mount = ctypes.c_uint64()
    # AT_EMPTY_PATH | AT_HANDLE_MNT_ID_UNIQUE: identify this fd, not a second path lookup.
    if _NAME_TO_HANDLE_AT(fd, b"", ctypes.byref(handle), ctypes.byref(mount), 0x1000 | 0x001) != 0:
        return None
    if not mount.value or not 0 < handle.size <= len(handle.data):
        return None
    return mount.value, struct.pack("!i", handle.kind) + bytes(handle.data[:handle.size])


def _ext4_generation_handle(fid: bytes) -> bool:
    # FILEID_INO32_GEN contains exactly the inode number and generation.
    return len(fid) == 12 and fid[:4] == struct.pack("!i", 1) and any(fid[-4:])


def _root_anchor(key_fd: int) -> tuple[int, bytes] | None:
    """Only the host root mount carrying our private key can anchor grants across boots."""
    try:
        root = os.open("/", _DIRECTORY_FLAGS)
    except OSError:
        return None
    try:
        # Do not infer durability from arbitrary export handles (e.g. network/overlay filesystems).
        with open("/proc/self/mountinfo", "rb") as mounts:
            roots = [fields for fields in map(bytes.split, mounts) if fields[4] == b"/"]
        with open(f"/proc/self/fdinfo/{root}", "rb") as info:
            mount_ids = [line.split()[1] for line in info if line.startswith(b"mnt_id:")]
        if (len(roots) != 1 or mount_ids != [roots[0][0]] or roots[0][3] != b"/"
                or roots[0][roots[0].index(b"-") + 1] != b"ext4"):
            return None
        root_handle, key_handle = _file_handle(root), _file_handle(key_fd)
        if (not root_handle or not key_handle or root_handle[0] != key_handle[0]
                or not _ext4_generation_handle(key_handle[1])):
            return None
        # Linux FS_IOC_GETFSUUID (_IOR(0x15, 0, struct fsuuid2)); unknown ABI => boot-only.
        fsuuid = fcntl.ioctl(root, 0x80111500, bytes(17))
        if fsuuid[0] != 16 or not any(fsuuid[1:]):
            return None
        return root_handle[0], fsuuid[1:] + key_handle[1]
    except (OSError, IndexError, ValueError):
        return None
    finally:
        os.close(root)


def _durable_digest(anchor: tuple[int, bytes] | None, handle: tuple[int, bytes]) -> str | None:
    mount, fid = handle
    # A bind mount of even the original directory cannot match this mount ID.
    if not anchor or mount != anchor[0] or not _ext4_generation_handle(fid):
        return None
    return hashlib.sha256(anchor[1] + fid).hexdigest()


class _ExpiredPin(HelperError):
    def __init__(self):
        super().__init__("unavailable", "Session-only approval expired; reattach with the host CLI.")


class _SessionPin:
    """Own an exact directory descriptor until activation is abandoned or the grant is detached."""

    def __init__(self, fd: int, attachment_id: str, info: os.stat_result):
        self.fd = os.dup(fd)
        self.close = weakref.finalize(self, os.close, self.fd)
        self.attachment_id = attachment_id
        self.info = info
        self.expires = time.monotonic() + STAGED_PIN_SECONDS


def _proof_key(directory: str) -> tuple[bytes, tuple[int, bytes] | None]:
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
        anchor = _root_anchor(handle.fileno())
    if len(key) != 32:
        raise ValueError("Invalid host folder approval key.")
    return key, anchor


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
                                or self.is_retired(entry["attachment_id"])):
                            del self.data[variant_id][alias]
                            rewrite = True
        except FileNotFoundError:
            pass
        except (OSError, ValueError) as exc:
            raise ValueError(f"Cannot read helper registry {self.path}: {exc}") from exc
        if rewrite:
            self._save()

    def is_retired(self, attachment_id: str) -> bool:
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
            if self.is_retired(attachment_id) or (previous and (
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
                if name and not _excluded(name, file_candidate=True):
                    self._tick()
                    info = os.stat(name, dir_fd=directory, follow_symlinks=False)
                    if stat.S_ISREG(info.st_mode) and not _excluded_config(name, info):
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
            if _excluded(entry.name, file_candidate=True):
                continue
            try:
                is_dir = entry.is_dir(follow_symlinks=False)
                is_file = not is_dir and entry.is_file(follow_symlinks=False)
            except OSError:
                self.io_errors += 1
                continue
            if is_dir:
                if exhausted or entry.name == ".config":
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
                    info = entry.stat(follow_symlinks=False)
                    if stat.S_ISREG(info.st_mode) and not _excluded_config(entry.name, info):
                        yield path, info.st_size
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
    advice = ("narrow folder or pattern using a literal prefix from the attachment's returned paths "
              "or attach a smaller folder.")
    if reason == "entries":
        return f"The {operation} stopped after visiting {MAX_WALK_ENTRIES} entries{detail}; {advice}"
    if reason == "bytes":
        return f"The next file would exceed the search byte budget{detail}; narrow the pattern."
    if reason == "results":
        return f"The {operation} reached its match limit{detail}; narrow the query or pattern."
    seconds = SEARCH_TIME_LIMIT if operation == "search" else LIST_TIME_LIMIT
    return f"The {operation} stopped at its {seconds:g}s time limit{detail}; incomplete, not absence; {advice}"


def _walk_message(message: str | None, walk: _Walk) -> str | None:
    warnings = [message] if message else []
    if walk.io_errors:
        warnings.append(f"Incomplete: {walk.io_errors} I/O error(s) while accessing files or folders.")
    if walk.skipped_paths:
        warnings.append(f"Incomplete: skipped {walk.skipped_paths} file path(s) that cannot be represented.")
    return " ".join(warnings) or None


class Helper:
    """Request dispatcher for exact host-approved attachments."""

    def __init__(self, state_dir: str, *, engine: str | None = None, image: str | None = None,
                 snapshot_mib: int = DEFAULT_SNAPSHOT_MIB):
        if snapshot_mib < 1:
            raise ValueError("Shell snapshot limit must be a positive number of MiB.")
        self.snapshot_bytes = snapshot_mib * 1024 * 1024
        self.state_dir = state_dir
        self.engine = engine
        self.image = image
        self.registry = Registry(state_dir)
        self._key, self._anchor = _proof_key(state_dir)
        self._snapshot_prefix = "shell-" + hmac.digest(self._key, b"snapshot-directory", "sha256")[:16].hex() + "-"
        self._shell_condition = threading.Condition()
        self._active_shells = 0
        self._closing_shells = False
        self._boot = _boot_id()
        self._boot_tag = hmac.digest(self._key, self._boot, "sha256")[:16].hex() if self._boot else None
        self.permit_epoch = uuid.uuid4().hex
        self._pins: dict[str, _SessionPin] = {}
        self._pin_lock = threading.Lock()
        self._mutation_lock = threading.Lock()
        self.operations: dict[str, Callable[[dict], dict]] = {
            "status": self.status, "detach": self.detach,
            "source": self.source, "stage": self.stage, "activate": self.activate,
            "list": self.list_files, "read": self.read,
            "shell": self.shell,
        }

    # -- dispatch -----------------------------------------------------------------------------

    def dispatch(self, request: object, *, reply: Callable[[dict], None] | None = None) -> dict:
        with ExitStack() as admission:
            try:
                if not isinstance(request, dict):
                    raise HelperError("invalid", "Request must be a JSON object.")
                op = request.get("op")
                operation = self.operations.get(op)  # type: ignore[arg-type]
                if operation is None:
                    raise HelperError("invalid", "Unknown operation; the helper is read-only.")
                if op == "shell" and reply is not None:
                    # Shutdown must wait for the socket reply, not just the job.
                    admission.enter_context(self._admit_shell())
                    operation = self._shell_job
                response = {"ok": True, "result": operation(request)}
            except HelperError as exc:
                response = {"ok": False, "code": exc.code, "error": exc.message}
            except Exception as exc:  # pragma: no cover - defensive: never leak tracebacks to clients
                _log(f"internal error: {type(exc).__name__}: {exc}")
                response = {"ok": False, "code": "internal", "error": "Internal helper error; see the helper log."}
            if reply is not None:
                reply(response)
            return response

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
        if not self._pin_lock.acquire(blocking=False):
            return
        try:
            now = time.monotonic()
            expired = [self._pins.pop(key) for key, pin in list(self._pins.items()) if pin.expires <= now]
        finally:
            self._pin_lock.release()
        for pin in expired:
            pin.close()

    def _approval_identity(self, fd: int, attachment_id: str) -> str:
        handle = _file_handle(fd)
        if self._boot is not None and handle:
            scoped = self._boot_digest(handle)
            durable = _durable_digest(self._anchor, handle)
            return f"d{self._boot_tag}.{scoped}.{durable}" if durable else f"b{self._boot_tag}.{scoped}"
        self.expire_pending_pins()
        info = os.fstat(fd)
        with self._pin_lock:
            for key, pin in self._pins.items():
                if pin.attachment_id == attachment_id and os.path.samestat(info, pin.info):
                    pin.expires = max(pin.expires, time.monotonic() + STAGED_PIN_SECONDS)
                    return key
            if len(self._pins) >= MAX_SESSION_PINS:
                raise HelperError("limit", "Session-only folder limit reached; detach unused folders and retry.")
            key = "s" + uuid.uuid4().hex
            self._pins[key] = _SessionPin(fd, attachment_id, info)
            return key

    def _boot_digest(self, handle: tuple[int, bytes]) -> str:
        assert self._boot is not None
        return hashlib.sha256(self._boot + struct.pack("!Q", handle[0]) + handle[1]).hexdigest()

    def _check_handle(self, fd: int, identity: str) -> None:
        handle = _file_handle(fd)
        if not handle or self._boot is None or not re.fullmatch(_IDENTITY, identity):
            raise HelperError("unavailable", _UNVERIFIED)
        if identity.startswith("h"):
            # Legacy signatures contain neither a separate boot tag nor a durable anchor.
            if identity[1:] != self._boot_digest(handle):
                raise HelperError("unavailable", _LEGACY)
            return
        tag, scoped, *durable = identity[1:].split(".")
        if tag == self._boot_tag:
            if scoped != self._boot_digest(handle):
                raise HelperError("unavailable", _MOVED)
        elif not durable or (current := _durable_digest(self._anchor, handle)) is None:
            raise HelperError("unavailable", _REBOOT)
        elif current != durable[0]:
            raise HelperError("unavailable", "Folder or host filesystem identity changed; verify it and reattach "
                              "with the host CLI.")

    def _open_approved(self, path: str, identity: str) -> int:
        fd = self._open_folder(path)
        try:
            if identity.startswith("s"):
                with self._pin_lock:
                    pin = self._pins.get(identity)
                    if pin is None or pin.expires <= time.monotonic():
                        raise _ExpiredPin()
                    pinned_fd = os.dup(pin.fd)
                try:
                    info = os.fstat(pinned_fd)
                    if info.st_nlink and os.path.samestat(info, os.fstat(fd)):
                        # Serve the pinned object, never merely one reporting the same inode.
                        return os.open(".", _DIRECTORY_FLAGS, dir_fd=pinned_fd)
                finally:
                    os.close(pinned_fd)
            else:
                self._check_handle(fd, identity)
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

    def _shell_root(self, request: dict) -> int:
        if request.get("source") != "mount" or "directory" in request:
            raise HelperError("forbidden", "Shell inspection requires an approved host attachment.")
        _string(request, "mount_path")
        return self._scoped_fd(request)[0]

    def _shell_snapshot(self, root: int, destination: str) -> dict:
        walk = _Walk(root, LIST_TIME_LIMIT)
        budget = self.snapshot_bytes
        copied = 0
        try:
            for path, size in walk.files(""):
                if size > budget:
                    raise _Exhausted("bytes")
                parts = _relative_path(path)
                directory = os.path.join(destination, *parts[:-1])
                os.makedirs(directory, mode=0o755, exist_ok=True)
                current = destination
                for part in parts[:-1]:
                    current = os.path.join(current, part)
                    os.chmod(current, 0o755)
                with self._open_member(root, parts, reject_hardlinks=True) as fd:
                    before = os.fstat(fd)
                    if before.st_nlink != 1:
                        raise HelperError("invalid", "Links cannot be copied into a shell snapshot.")
                    written = 0
                    with open(os.path.join(directory, parts[-1]), "xb") as target:
                        while True:
                            walk.check_time()
                            chunk = os.read(fd, min(SNAPSHOT_CHUNK, budget + 1))
                            walk.check_time()
                            if not chunk:
                                break
                            if len(chunk) > budget:
                                raise _Exhausted("bytes")
                            target.write(chunk)
                            budget -= len(chunk)
                            written += len(chunk)
                    walk.check_time()
                    after = os.fstat(fd)
                    if (after.st_nlink != 1 or written != before.st_size or after.st_size != written
                            or before.st_mtime_ns != after.st_mtime_ns or before.st_ctime_ns != after.st_ctime_ns):
                        raise HelperError("unavailable", "Source changed while preparing the shell snapshot; retry.")
                os.chmod(os.path.join(directory, parts[-1]), 0o644)
                copied += 1
            if walk.io_errors or walk.skipped_paths:
                raise HelperError("unavailable", "Source snapshot is incomplete due to inaccessible paths.")
        except _Exhausted as exc:
            limit = {"bytes": f"{self.snapshot_bytes} bytes", "entries": f"{MAX_WALK_ENTRIES} entries",
                     "time": f"{LIST_TIME_LIMIT:g}s copy/traversal time"}[str(exc)]
            raise HelperError("limit", f"Shell snapshot limit ({limit}) reached; inspection incomplete. "
                              "Choose a smaller folder or use search_codebase_file for a known log.") from exc
        except OSError as exc:
            raise HelperError("unavailable", "Shell snapshot incomplete: source or destination I/O failure.") from exc
        return {"files": copied, "bytes": self.snapshot_bytes - budget,
                "excluded": "Hidden names except single-link regular .config files are excluded, "
                            "as are sensitive names, links and special files."}

    @contextmanager
    def _locked_state(self) -> Iterator[int]:
        # A writable regular file keeps exclusive flock usable on NFS, unlike a read-only directory descriptor.
        lock = os.open(os.path.join(self.state_dir, ".snapshots.lock"),
                       os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | _CLOEXEC, 0o600)
        state = -1
        try:
            fcntl.flock(lock, fcntl.LOCK_EX)
            state = os.open(self.state_dir, _DIRECTORY_FLAGS)
            yield state
        finally:
            if state >= 0:
                os.close(state)
            os.close(lock)

    def reap_shell_snapshots(self) -> None:
        # Never infer ownership from the old generic shell-* temporary names.
        with self._locked_state() as state:
            with os.scandir(state) as entries:
                for entry in entries:
                    if not re.fullmatch(self._snapshot_prefix + "[0-9a-f]{32}", entry.name):
                        continue
                    if not entry.is_dir(follow_symlinks=False):
                        continue
                    try:
                        fd = os.open(entry.name, _DIRECTORY_FLAGS, dir_fd=state)
                    except FileNotFoundError:
                        continue
                    try:
                        if os.fstat(fd).st_uid != os.geteuid():
                            continue
                        try:
                            lease = os.open(_LEASE_NAME, os.O_RDWR | os.O_NOFOLLOW | _CLOEXEC, dir_fd=fd)
                        except FileNotFoundError:
                            lease = -1
                        try:
                            if lease >= 0:
                                try:
                                    fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
                                except BlockingIOError:
                                    continue
                            shutil.rmtree(os.path.join(self.state_dir, entry.name))
                        finally:
                            if lease >= 0:
                                os.close(lease)
                    finally:
                        os.close(fd)

    @contextmanager
    def _snapshot_workspace(self) -> Iterator[str]:
        name = self._snapshot_prefix + uuid.uuid4().hex
        path = os.path.join(self.state_dir, name)
        # Publish the directory and its lease atomically with respect to a starting helper.
        with self._locked_state() as state:
            os.mkdir(name, 0o700, dir_fd=state)
            try:
                directory = os.open(name, _DIRECTORY_FLAGS, dir_fd=state)
                try:
                    lease = os.open(_LEASE_NAME, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | _CLOEXEC,
                                    0o600, dir_fd=directory)
                finally:
                    os.close(directory)
                try:
                    fcntl.flock(lease, fcntl.LOCK_EX)
                except BaseException:
                    os.close(lease)
                    raise
            except BaseException:
                shutil.rmtree(path, ignore_errors=True)
                raise
        try:
            yield path
        finally:
            try:
                shutil.rmtree(path)
            finally:
                os.close(lease)

    def drain_shells(self) -> None:
        deadline = time.monotonic() + SHELL_DRAIN_TIMEOUT
        with self._shell_condition:
            self._closing_shells = True
            # Jobs blocked in source I/O cannot be interrupted; their leases die with this process.
            self._shell_condition.wait_for(lambda: self._active_shells == 0,
                                           timeout=max(0.0, deadline - time.monotonic()))

    @contextmanager
    def _admit_shell(self) -> Iterator[None]:
        with self._shell_condition:
            if self._closing_shells:
                raise HelperError("unavailable", "The host helper is stopping.")
            self._active_shells += 1
        try:
            yield
        finally:
            with self._shell_condition:
                self._active_shells -= 1
                self._shell_condition.notify_all()

    def shell(self, request: dict) -> dict:
        with self._admit_shell():
            return self._shell_job(request)

    def _shell_job(self, request: dict) -> dict:
        if not self.engine or not self.image:
            raise HelperError("unavailable", "Read-only shell worker is not configured; restart the host helper.")
        command = _string(request, "command", maximum=4096)
        root = self._shell_root(request)
        try:
            with self._snapshot_workspace() as temporary:
                snapshot = os.path.join(temporary, "source")
                os.mkdir(snapshot, 0o755)
                os.chmod(temporary, 0o755)
                os.chmod(snapshot, 0o755)
                metadata = self._shell_snapshot(root, snapshot)
                return {**self._run_shell(snapshot, command), "snapshot": metadata}
        finally:
            os.close(root)

    def _empty_mounts_file(self) -> str:
        path = os.path.join(self.state_dir, ".empty-mounts.conf")
        try:
            fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | _CLOEXEC, 0o600)
            try:
                if os.fstat(fd).st_size:
                    os.ftruncate(fd, 0)
            finally:
                os.close(fd)
        except OSError as exc:
            raise HelperError("unavailable", "Cannot prepare the shell worker mount policy.") from exc
        return path

    def _run_shell(self, snapshot: str, command: str) -> dict:
        if not self.engine or not self.image:
            raise HelperError("unavailable", "Read-only shell worker is not configured.")
        if "," in snapshot:
            raise HelperError("invalid", "Shell worker state path cannot contain a comma.")
        env = os.environ.copy()
        engine_name = os.path.basename(self.engine)
        if engine_name == "docker":
            endpoint = env.get("DOCKER_HOST")
            if not endpoint:
                try:
                    inspection = subprocess.run(
                        [self.engine, "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"],
                        stdin=subprocess.DEVNULL, capture_output=True, timeout=5, check=True, text=True,
                    )
                except (OSError, subprocess.SubprocessError) as exc:
                    raise HelperError("unavailable", "Cannot verify the local Docker endpoint.") from exc
                endpoint = inspection.stdout.strip()
            if not endpoint.startswith("unix:///"):
                raise HelperError("unavailable", "The shell worker requires a local Docker Unix socket.")
            env.pop("DOCKER_HOST", None)
            env.pop("DOCKER_CONTEXT", None)
            engine = [self.engine, "--host", endpoint]
        elif engine_name == "podman":
            if env.get("CONTAINER_HOST") or env.get("CONTAINER_CONNECTION"):
                raise HelperError("unavailable", "The shell worker does not support remote Podman connections.")
            engine = [self.engine, "--remote=false"]
        else:
            raise HelperError("unavailable", "The shell worker requires Docker or Podman.")
        name = f"vulnscout-shell-{uuid.uuid4().hex}"
        # Podman copies image contents into tmpfs by default: keep both masks empty.
        mask_options = "ro,nosuid,nodev,noexec,size=4k" + (",notmpcopyup" if engine_name == "podman" else "")
        snapshot_mount = f"type=bind,src={snapshot},dst=/source,readonly"
        if engine_name == "podman":
            snapshot_mount += ",relabel=private"  # Relabel the disposable copy, never the approved source.
        if engine_name == "podman":
            # Podman would otherwise forward host proxy variables and mount mounts.conf entries (for example
            # subscription credentials) into the worker; fail closed if the override cannot be applied.
            run_options = ["--http-proxy=false", f"--default-mounts-file={self._empty_mounts_file()}"]
        else:
            # Docker injects the CLI's configured proxies unless the variables are set explicitly.
            run_options = [f"--env={variable}=" for variable in _PROXY_VARIABLES]
        args = engine + [
            "run", "--rm", "--name", name, "--pull=never", *run_options,
            "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
            "--pids-limit=64", "--memory=256m", "--cpus=1", "--user=65534:65534",
            "--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=16m",
            f"--tmpfs=/scan:{mask_options}",
            f"--tmpfs=/cache:{mask_options}",
            "--mount", snapshot_mount,
            "--workdir=/source", "--entrypoint=/usr/bin/timeout", self.image,
            "-s", "KILL", str(int(SHELL_TIMEOUT)), "/bin/sh", "-c", command,
        ]
        output = bytearray()
        truncated = False
        timed_out = False
        try:
            process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, close_fds=True, env=env)
        except OSError as exc:
            raise HelperError("unavailable", "Cannot start the isolated shell worker.") from exc
        assert process.stdout is not None
        deadline = time.monotonic() + SHELL_TIMEOUT
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        timed_out = True
                        break
                    events = selector.select(remaining)
                    if not events:
                        timed_out = True
                        break
                    data = os.read(process.stdout.fileno(), min(8192, SHELL_OUTPUT_BYTES + 1 - len(output)))
                    if not data:
                        break
                    output.extend(data)
                    if len(output) > SHELL_OUTPUT_BYTES:
                        truncated = True
                        break
            if not timed_out and not truncated:
                try:
                    process.wait(timeout=max(0.01, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    timed_out = True
        finally:
            if process.poll() is None or timed_out or truncated:
                if process.poll() is None:
                    process.kill()
                process.wait()
                process.stdout.close()
                try:
                    remove = ["rm", "-f"] + (["--time", "0"] if engine_name == "podman" else []) + [name]
                    cleanup = subprocess.run(engine + remove, stdin=subprocess.DEVNULL,
                                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
                                             check=False, env=env)
                    if (cleanup.returncode and b"No such container" not in cleanup.stderr
                            and b"no container with name" not in cleanup.stderr.lower()):
                        raise HelperError("unavailable", "Could not stop the shell worker; check the container engine.")
                except (OSError, subprocess.TimeoutExpired) as exc:
                    raise HelperError(
                        "unavailable", "Could not stop the shell worker; check the container engine."
                    ) from exc
            process.wait()
            process.stdout.close()
        return {"output": bytes(output[:SHELL_OUTPUT_BYTES]).decode("utf-8", errors="replace"),
                "exit_code": process.returncode, "truncated": truncated, "timed_out": timed_out,
                **({"message": f"Shell command timed out at {SHELL_TIMEOUT:g}s; output is incomplete, not absence."}
                   if timed_out else {})}

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
        if not approval.startswith(self.permit_epoch.encode() + b"\0"):
            raise HelperError("forbidden", "Stale host permit; rerun attach with the matching host launcher.")
        if (approval != b"\0".join((self.permit_epoch.encode(), variant_id.encode(), os.fsencode(path)))
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
                or not (match := re.fullmatch(rf"({_IDENTITY}):[a-f0-9]{{64}}", proof))
                or not hmac.compare_digest(proof, self._proof(attachment_id, variant_id, alias, path, match[1]))):
            raise HelperError("forbidden", "No valid host approval; reattach this folder with the host CLI.")
        try:
            self._publish_approval(path, variant_id, alias, attachment_id, match[1])
        except _ExpiredPin:
            if self.registry.is_retired(attachment_id):
                raise HelperError("unavailable", "Attachment has been detached or replaced.") from None
            raise
        return {"path": path}

    def _publish_approval(self, path: str, variant_id: str, alias: str, attachment_id: str, identity: str) -> None:
        os.close(self._open_approved(path, identity))
        # Order registry publication and pin retirement, but never wait for the
        # attached filesystem while holding either shared lock.
        with self._mutation_lock:
            with self._pin_lock:
                pin = self._pins.get(identity)
                if identity.startswith("s") and (pin is None or pin.expires <= time.monotonic()):
                    raise _ExpiredPin()
                if pin is not None:
                    previous_expiry = pin.expires
                    pin.expires = float("inf")
            try:
                self.registry.set(variant_id, alias, path, attachment_id=attachment_id, identity=identity)
            except BaseException:
                if pin is not None:
                    with self._pin_lock:
                        pin.expires = previous_expiry
                raise
            with self._pin_lock:
                retired = [self._pins.pop(key) for key, old in list(self._pins.items())
                           if key != identity and old.attachment_id == attachment_id and old.expires == float("inf")]
        for old in retired:
            old.close()

    def detach(self, request: dict) -> dict:
        variant_id = _variant_id(request)
        alias = validate_alias(request.get("alias"))
        attachment_id = _string(request, "attachment_id", maximum=36)
        with self._mutation_lock:
            removed = self.registry.remove(variant_id, alias, attachment_id=attachment_id, retire=True)
            with self._pin_lock:
                retired = [self._pins.pop(key) for key, pin in list(self._pins.items())
                           if pin.attachment_id == attachment_id]
        for pin in retired:
            pin.close()
        return {"removed": removed}

    def source(self, request: dict) -> dict:
        """Require the current host-approved alias to match the database mount path."""
        _string(request, "mount_path")
        operation = request.get("source_operation")
        if operation not in ("list", "read", "read_position", "children", "search_file", "search"):
            raise HelperError("invalid", "Unsupported source operation.")
        return {
            "list": self.list_files,
            "read": self.read,
            "read_position": self.read,
            "children": self.list_children,
            "search_file": self.search_file,
            "search": self.search,
        }[operation](request)

    def list_children(self, request: dict) -> dict:
        fd, base = self._scoped_fd(request)
        try:
            return children_page(fd, base, request, f"{_variant_id(request)}/mount:{request['alias']}")
        except OSError as exc:
            raise HelperError("unavailable", "Folder changed or cannot be inspected; retry this lookup.") from exc
        finally:
            os.close(fd)

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

    @contextmanager
    def _approved_member(self, request: dict, parts: list[str]) -> Iterator[int]:
        root = self._attachment_fd(request)
        try:
            with self._open_member(root, parts, reject_hardlinks=True) as fd:
                yield fd
        except OSError as exc:
            raise HelperError("unavailable", "Source file could not be inspected.") from exc
        finally:
            os.close(root)

    def search_file(self, request: dict) -> dict:
        parts = _relative_path(_string(request, "path", maximum=1024))
        with self._approved_member(request, parts) as fd:
            return search_file_page(fd, f"{_variant_id(request)}/mount:{request['alias']}", request)

    @staticmethod
    @contextmanager
    def _open_member(root_fd: int, parts: list[str], *, reject_hardlinks: bool) -> Iterator[int]:
        directory_fd = root_fd
        opened: list[int] = []
        try:
            for part in parts[:-1]:
                directory_fd = os.open(part, _DIRECTORY_FLAGS, dir_fd=directory_fd)
                opened.append(directory_fd)
            entry = os.open(parts[-1], os.O_PATH | os.O_NOFOLLOW | _CLOEXEC, dir_fd=directory_fd)
            try:
                info = os.fstat(entry)
                if not stat.S_ISREG(info.st_mode) or (reject_hardlinks and info.st_nlink != 1):
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
            yield fd
        finally:
            os.close(fd)

    def _read_file(self, root_fd: int, parts: list[str], budget: list[int] | None = None) -> bytes:
        with self._open_member(root_fd, parts, reject_hardlinks=budget is not None or parts[-1] == ".config") as fd:
            info = os.fstat(fd)
            if _excluded_config(parts[-1], info):
                raise HelperError("invalid", "Links cannot be read as .config files.")
            if info.st_size > MAX_FILE_BYTES:
                raise HelperError("limit", DIRECT_READ_LIMIT_MESSAGE)
            limit = MAX_FILE_BYTES + 1
            if budget is not None:
                if info.st_size > budget[0]:
                    raise _Exhausted("bytes")
                limit = min(limit, budget[0])
            content = os.read(fd, limit)
            if budget is not None:
                budget[0] -= len(content)
                if len(content) == limit and os.fstat(fd).st_size > len(content):
                    raise _Exhausted("bytes")
            if len(content) > MAX_FILE_BYTES:
                raise HelperError("limit", DIRECT_READ_LIMIT_MESSAGE)
            if len(content) < info.st_size:
                raise HelperError("unavailable", "Source file could not be read in full.")
            if parts[-1] == ".config":
                after = os.fstat(fd)
                if after.st_nlink != 1 or after.st_ctime_ns != info.st_ctime_ns:
                    raise HelperError("unavailable", "Source file changed during read.")
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
        if request.get("source_operation") == "read_position" or "position" in request:
            position = _string(request, "position", maximum=160)
            if _folder_parts(request):
                raise HelperError("invalid", "Use an exact path, not folder, for a positioned read.")
            if start_line != 1:
                raise HelperError("invalid", "Use position or start_line, not both.")
            scope = f"{_variant_id(request)}/mount:{validate_alias(request.get('alias'))}"
            return read_position(lambda: self._approved_member(request, parts), scope, path, position, max_lines)
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
        query = _string(request, "query", maximum=200)
        matcher, pattern = _pattern(request)
        max_results = _integer(request, "max_results", 100, 1, 100)
        fd, base = self._scoped_fd(request)
        matches: list[dict] = []
        searched = skipped_binary = skipped_large = 0
        budget = [SEARCH_BYTE_BUDGET]
        walk = _Walk(fd, SEARCH_TIME_LIMIT, matcher, pattern)
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
                    if query in line:
                        if len(matches) == max_results:
                            raise _Exhausted("results")
                        matches.append({"path": base + path, "line": number, "text": line.rstrip("\r\n")[:500]})
        except _Exhausted as exc:
            message = _exhausted_message(str(exc), "search", walk)
        finally:
            os.close(fd)
        message = _walk_message(message, walk)
        result = {
            "matches": matches, "truncated": message is not None, "searched_files": searched, "engine": walk.engine,
            "skipped_binary_files": skipped_binary, "skipped_large_files": skipped_large,
            "skipped_paths": walk.skipped_paths, "io_errors": walk.io_errors,
            "bytes_read": SEARCH_BYTE_BUDGET - budget[0],
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
                server.helper.dispatch(request, reply=self._write_reply)
                return
        self._write_reply(response)

    def _write_reply(self, response: dict) -> None:
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


@contextmanager
def _socket_create_label(label: str | None) -> Iterator[None]:
    """Label the socket endpoint, not its filesystem entry or the helper process."""
    if not label:
        yield
        return
    lib = ctypes.CDLL("libselinux.so.1", use_errno=True)
    previous = ctypes.c_char_p()
    if lib.getsockcreatecon_raw(ctypes.byref(previous)) < 0:
        raise OSError(ctypes.get_errno(), "Cannot read the SELinux socket creation context")
    try:
        if lib.setsockcreatecon_raw(label.encode("ascii")) < 0:
            raise OSError(ctypes.get_errno(), f"Cannot create helper socket with SELinux label {label}")
        try:
            yield
        finally:
            if lib.setsockcreatecon_raw(previous) < 0:
                raise OSError(ctypes.get_errno(), "Cannot restore the SELinux socket creation context")
    finally:
        lib.freecon(previous)


class HelperServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    request_queue_size = 32

    def serve_forever(self, poll_interval: float = 0.5) -> None:
        stopped = threading.Event()

        def sweep() -> None:
            # Even closing the last descriptor can wait on a remote filesystem.
            while not stopped.wait(1):
                self.helper.expire_pending_pins()

        threading.Thread(target=sweep, daemon=True).start()
        try:
            super().serve_forever(poll_interval)
        finally:
            stopped.set()

    def __init__(self, socket_path: str, helper: Helper, socket_label: str | None = None):
        self.helper = helper
        self.socket_path = socket_path
        self.slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self.socket_name = os.path.basename(socket_path)
        self.directory_fd: int | None = None
        self.bound_socket: os.stat_result | None = None
        with _socket_create_label(socket_label):
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
            try:
                connection.connect(address)
            except socket.timeout as exc:
                raise ConnectionError(f"Connection to the host helper timed out after {timeout:g}s.") from exc
            try:
                connection.sendall(json.dumps(payload).encode("utf-8") + b"\n")
            except socket.timeout as exc:
                raise ConnectionError(f"Sending the host helper request timed out after {timeout:g}s; "
                                      "result incomplete.") from exc
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
        helper = Helper(args.state_dir, engine=args.engine, image=args.image, snapshot_mib=args.snapshot_mib)
        helper.reap_shell_snapshots()
        server = HelperServer(os.path.abspath(args.socket), helper, args.socket_label)
        # The host launcher reads this before issuing its one-shot permits. An
        # interrupted attach from a previous helper must never mint a new proof.
        with open(os.path.join(args.state_dir, "permit.epoch"), "w", encoding="ascii") as epoch:
            epoch.write(helper.permit_epoch + "\n")
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
        helper.drain_shells()
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
    serve.add_argument("--socket-label", help="Container process SELinux label for the listening socket only.")
    serve.add_argument("--state-dir", required=True, help="Host-only directory holding the alias registry.")
    serve.add_argument("--engine", help="Host container engine executable for the shell worker.")
    serve.add_argument("--image", help="Trusted local image ID for the shell worker.")
    serve.add_argument("--snapshot-mib", type=int, default=DEFAULT_SNAPSHOT_MIB, help="Shell snapshot byte cap in MiB.")
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
