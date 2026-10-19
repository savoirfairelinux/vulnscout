# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Bounded, read-only access to uploaded source files without extraction."""

import gzip
import io
import stat
import tarfile
import tempfile
import zipfile
import zlib
from contextlib import ExitStack
from fnmatch import fnmatchcase
from pathlib import PurePosixPath
from typing import IO

MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_EXPANDED_BYTES = 100 * 1024 * 1024
MAX_ENTRIES = 5000
MAX_RESPONSE_BYTES = 64 * 1024
ARCHIVE_SUFFIXES = (".zip", ".tar", ".tar.gz", ".tgz")


def _safe_path(name: str) -> str:
    path = PurePosixPath(name)
    if (not name or "\\" in name or any(ord(char) < 32 for char in name)
            or len(name.encode("utf-8")) > 512 or path.is_absolute()
            or ".." in path.parts or ":" in name or not path.parts):
        raise ValueError("Archive contains an unsafe path.")
    return str(path)


class CodebaseReference:
    def __init__(self, stream: IO[bytes], name: str):
        self.stream = stream
        self.name = name
        self.stack = ExitStack()
        self.archive: zipfile.ZipFile | tarfile.TarFile | None = None
        self.entries: dict[str, tuple[int, zipfile.ZipInfo | tarfile.TarInfo | None]] = {}
        self.total_bytes = 0

    def __enter__(self) -> "CodebaseReference":
        try:
            self._index()
        except (OSError, EOFError, tarfile.TarError, zipfile.BadZipFile, zlib.error, NotImplementedError) as exc:
            self.stack.close()
            raise ValueError("Invalid or unsupported source archive.") from exc
        except ValueError:
            self.stack.close()
            raise
        return self

    def __exit__(self, *args) -> None:
        self.stack.close()

    def _add(self, name: str, size: int, member: zipfile.ZipInfo | tarfile.TarInfo | None) -> None:
        path = _safe_path(name)
        if path in self.entries:
            raise ValueError("Archive contains duplicate file paths.")
        if size < 0:
            raise ValueError("Archive contains an invalid file size.")
        if member is not None and size > MAX_FILE_BYTES:
            raise ValueError("Archive contains an invalid file size.")
        self.entries[path] = (size, member)
        self.total_bytes += size
        if self.total_bytes > MAX_EXPANDED_BYTES:
            raise ValueError("Archive exceeds the maximum expanded size.")

    def _index(self) -> None:
        name = self.name.lower()
        self.stream.seek(0)
        if name.endswith(".zip"):
            archive = self.stack.enter_context(zipfile.ZipFile(self.stream))
            self.archive = archive
            if len(archive.infolist()) > MAX_ENTRIES:
                raise ValueError("Archive contains more than 5000 entries.")
            for member in archive.infolist():
                if member.is_dir() and member.filename in (".", "./"):
                    continue
                _safe_path(member.filename)
                mode = member.external_attr >> 16
                if (member.flag_bits & 1 or stat.S_ISLNK(mode)
                        or (stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR))):
                    raise ValueError("Encrypted files, links and special archive entries are not supported.")
                if not member.is_dir():
                    self._add(member.filename, member.file_size, member)
        elif name.endswith((".tar", ".tar.gz", ".tgz")):
            source = self.stream
            if name.endswith((".tar.gz", ".tgz")):
                source = self.stack.enter_context(tempfile.SpooledTemporaryFile(max_size=MAX_FILE_BYTES))
                compressed = self.stack.enter_context(gzip.GzipFile(fileobj=self.stream))
                expanded = 0
                while chunk := compressed.read(1024 * 1024):
                    expanded += len(chunk)
                    if expanded > MAX_EXPANDED_BYTES:
                        raise ValueError("Archive exceeds the maximum expanded size.")
                    source.write(chunk)
                source.seek(0)
            tar = self.stack.enter_context(tarfile.open(fileobj=source, mode="r:"))
            self.archive = tar
            for count, entry in enumerate(tar, 1):
                if count > MAX_ENTRIES:
                    raise ValueError("Archive contains more than 5000 entries.")
                if entry.isdir() and entry.name in (".", "./"):
                    continue
                _safe_path(entry.name)
                if (not entry.isfile() and not entry.isdir()) or entry.issparse():
                    raise ValueError("Links, sparse files and special archive entries are not supported.")
                if entry.isfile():
                    self._add(entry.name, entry.size, entry)
        else:
            self.stream.seek(0, 2)
            self._add(self.name, self.stream.tell(), None)
        if not self.entries:
            raise ValueError("Source archive contains no files.")

    def read_bytes(self, path: str) -> bytes:
        if path not in self.entries:
            raise LookupError("Source file not found.")
        size, member = self.entries[path]
        if size > MAX_FILE_BYTES:
            raise ValueError("Source file exceeds the maximum readable file size.")
        try:
            if isinstance(self.archive, zipfile.ZipFile) and isinstance(member, zipfile.ZipInfo):
                with self.archive.open(member) as source:
                    content = source.read(MAX_FILE_BYTES + 1)
            elif isinstance(self.archive, tarfile.TarFile) and isinstance(member, tarfile.TarInfo):
                tar_source = self.archive.extractfile(member)
                if tar_source is None:
                    raise ValueError("Source file could not be read.")
                with tar_source:
                    content = tar_source.read(MAX_FILE_BYTES + 1)
            else:
                self.stream.seek(0)
                content = self.stream.read(MAX_FILE_BYTES + 1)
        except (OSError, EOFError, tarfile.TarError, zipfile.BadZipFile, zlib.error, NotImplementedError) as exc:
            raise ValueError("Source file could not be read.") from exc
        if len(content) != size:
            raise ValueError("Source file size does not match archive metadata.")
        return content

    def text(self, path: str) -> str:
        content = self.read_bytes(path)
        if b"\x00" in content:
            raise ValueError("Source file is binary; only UTF-8 text can be read.")
        try:
            return content.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise ValueError("Source file is not UTF-8 text.") from exc

    def list_files(self, pattern: str = "*", offset: int = 0, limit: int = 200) -> dict:
        paths = sorted(path for path in self.entries if fnmatchcase(path, pattern))
        selected = paths[offset:offset + limit]
        return {
            "files": [{"path": path, "size": self.entries[path][0]} for path in selected],
            "total": len(paths), "next_offset": offset + limit if offset + limit < len(paths) else None,
        }

    def read_lines(self, path: str, start_line: int = 1, max_lines: int = 200) -> dict:
        selected: list[str] = []
        length = 0
        total_lines = 0
        byte_limit = False
        for number, line in enumerate(io.StringIO(self.text(path)), 1):
            total_lines = number
            if number < start_line or len(selected) >= max_lines or byte_limit:
                continue
            length += len(line.encode("utf-8"))
            if length > MAX_RESPONSE_BYTES:
                if not selected:
                    raise ValueError("Source line exceeds the maximum response size of 64 KB.")
                byte_limit = True
            else:
                selected.append(line)
        end_line = start_line + len(selected) - 1
        return {
            "path": path, "start_line": start_line, "end_line": end_line,
            "content": "".join(selected), "total_lines": total_lines,
            "next_line": end_line + 1 if end_line < total_lines else None,
        }

    def search(self, query: str, pattern: str = "*", max_results: int = 100) -> dict:
        matches: list[dict] = []
        skipped = 0
        searched = 0
        for path in sorted(self.entries):
            if not fnmatchcase(path, pattern):
                continue
            content = self.read_bytes(path)
            try:
                text = content.decode("utf-8-sig")
            except UnicodeDecodeError:
                skipped += 1
                continue
            if "\x00" in text:
                skipped += 1
                continue
            searched += 1
            for number, line in enumerate(io.StringIO(text), 1):
                if query in line:
                    if len(matches) == max_results:
                        return {"matches": matches, "truncated": True,
                                "searched_files": searched, "skipped_binary_files": skipped}
                    matches.append({"path": path, "line": number, "text": line.rstrip("\r\n")[:500]})
        return {"matches": matches, "truncated": False,
                "searched_files": searched, "skipped_binary_files": skipped}


def validate_reference(stream: IO[bytes], name: str) -> None:
    with CodebaseReference(stream, name) as reference:
        if name.lower().endswith(ARCHIVE_SUFFIXES):
            for path in reference.entries:
                reference.read_bytes(path)
    stream.seek(0)
