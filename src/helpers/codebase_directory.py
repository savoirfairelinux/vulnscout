# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Bounded access to administrator-provided source, relative to pinned directory descriptors."""

import errno
import io
import os
import re
import stat
from contextlib import contextmanager, ExitStack

from .codebase_reference import CodebaseReference, MAX_ENTRIES, MAX_FILE_BYTES, _safe_path
from .host_mount_helper import children_page, _excluded

_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


class EmptyCodebaseDirectory(ValueError):
    """The directory was fully inspected but contains no eligible files."""


@contextmanager
def _open_directory(path: str, parent_fd: int | None = None):
    fd = os.open(path, _DIRECTORY_FLAGS, dir_fd=parent_fd)
    try:
        yield fd
    finally:
        os.close(fd)


def directory_name(project_name: str, variant_name: str) -> str:
    def slug(value: str) -> str:
        return re.sub(r"[^a-zA-Z0-9_-]+", "-", value).strip("-_")[:48] or "unnamed"

    return f"context-{slug(project_name)}-{slug(variant_name)}"


def directory_path(cache_dir: str, name: str) -> str:
    if not re.fullmatch(r"context-[a-zA-Z0-9_-]+", name):
        raise ValueError("Invalid codebase directory name.")
    return os.path.join(os.path.abspath(cache_dir), name)


def directory_exists(cache_dir: str, name: str) -> bool:
    """Check a readable directory without following links or creating paths."""
    directory_path(cache_dir, name)
    try:
        with _open_directory(cache_dir) as cache_fd:
            with _open_directory(name, cache_fd):
                return True
    except FileNotFoundError:
        return False


def provision_directory(cache_dir: str, name: str) -> None:
    directory_path(cache_dir, name)
    os.makedirs(cache_dir, mode=0o750, exist_ok=True)
    with _open_directory(cache_dir) as cache_fd:
        created = False
        try:
            os.mkdir(name, mode=0o750, dir_fd=cache_fd)
            created = True
        except FileExistsError:
            pass
        with _open_directory(name, cache_fd) as directory_fd:
            if created and os.geteuid() == 0:
                # setup_user maps the cache owner to the host user, including rootless Podman.
                # Only inherit it for new folders; existing source trees may be read-only mounts.
                owner = os.fstat(cache_fd)
                os.fchown(directory_fd, owner.st_uid, owner.st_gid)


class CodebaseDirectory(CodebaseReference):
    """Reuse the source response format, never following symlinks or opening special files."""

    def __init__(self, cache_dir: str, name: str, *, folder: str = "", index: bool = True):
        super().__init__(io.BytesIO(), name)
        directory_path(cache_dir, name)
        self.cache_dir = cache_dir
        self.folder = folder.rstrip("/")
        if folder and (not self.folder or _safe_path(self.folder) != self.folder
                       or any(_excluded(part) for part in self.folder.split("/"))):
            raise ValueError("Invalid or excluded codebase folder.")
        self.index = index
        self.root_fd = -1
        self.directory_count = 0

    def _index(self) -> None:
        cache_fd = self.stack.enter_context(_open_directory(self.cache_dir))
        self.root_fd = self.stack.enter_context(_open_directory(self.name, cache_fd))
        if self.folder:
            try:
                for part in self.folder.split("/"):
                    self.root_fd = self.stack.enter_context(_open_directory(part, self.root_fd))
            except FileNotFoundError as exc:
                raise LookupError("Codebase folder not found.") from exc
        if not self.index:
            return
        self._walk(self.root_fd, "", [0])
        if not self.entries and not self.folder:
            raise EmptyCodebaseDirectory("Codebase directory is empty or contains no eligible source files.")

    def __enter__(self) -> "CodebaseDirectory":
        try:
            self._index()
        except (OSError, ValueError, LookupError):
            self.stack.close()
            raise
        return self

    def _walk(self, directory_fd: int, prefix: str, visited: list[int]) -> None:
        with os.scandir(directory_fd) as entries:
            for entry in entries:
                visited[0] += 1
                if visited[0] > MAX_ENTRIES:
                    raise ValueError(
                        f"Codebase directory exceeds the {MAX_ENTRIES}-entry browsing limit; provide a smaller tree."
                    )
                if _excluded(entry.name):
                    continue
                path = _safe_path(prefix + entry.name)
                if self.folder:
                    _safe_path(self.folder + "/" + path)
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    with _open_directory(entry.name, directory_fd) as child_fd:
                        self.directory_count += 1
                        self._walk(child_fd, path + "/", visited)
                elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                    self.entries[path] = (info.st_size, None)

    def list_children(self, cursor: str, limit: int) -> dict:
        base = self.folder + "/" if self.folder else ""
        return children_page(self.root_fd, base, {"cursor": cursor, "limit": limit}, provisioned=True)

    def read_bytes(self, path: str) -> bytes:
        if self.index and path not in self.entries:
            raise LookupError("Source file not found or excluded.")
        try:
            parts = _safe_path(path).split("/")
        except ValueError as exc:
            raise LookupError("Source file not found or excluded.") from exc
        if "/".join(parts) != path or any(_excluded(part) for part in parts):
            raise LookupError("Source file not found or excluded.")
        with ExitStack() as stack:
            parent_fd = self.root_fd
            for part in parts[:-1]:
                parent_fd = stack.enter_context(_open_directory(part, parent_fd))
            entry = os.open(parts[-1], os.O_PATH | os.O_NOFOLLOW, dir_fd=parent_fd)
            try:
                info = os.fstat(entry)
                if stat.S_ISLNK(info.st_mode):
                    raise OSError(errno.ELOOP, "Source file is a symlink.")
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise ValueError("Links and special source files cannot be read.")
                fd = os.open(f"/proc/self/fd/{entry}", os.O_RDONLY)
            finally:
                os.close(entry)
            with io.FileIO(fd) as source:
                info = os.fstat(source.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise ValueError("Links and special source files cannot be read.")
                if info.st_size > MAX_FILE_BYTES:
                    raise ValueError("Source file exceeds the maximum readable file size of 10 MB.")
                content = source.read(MAX_FILE_BYTES + 1)
                if len(content) > MAX_FILE_BYTES:
                    raise ValueError("Source file exceeds the maximum readable file size of 10 MB.")
                return content

    def _iter_text_lines(self, path: str):
        content = self.read_bytes(path)
        if b"\x00" in content:
            raise ValueError("Source file is binary; only UTF-8 text can be read.")
        try:
            yield from io.StringIO(content.decode("utf-8-sig"))
        except UnicodeDecodeError as exc:
            raise ValueError("Source file is not UTF-8 text.") from exc
