from io import BytesIO
import stat
import tarfile
import zipfile

import pytest

from src.helpers.codebase_reference import CodebaseReference, validate_reference


def zip_source(entries):
    stream = BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries:
            archive.writestr(name, content)
    stream.seek(0)
    return stream


def tar_source(entries, mode="w"):
    stream = BytesIO()
    with tarfile.open(fileobj=stream, mode=mode) as archive:
        for name, content in entries:
            member = tarfile.TarInfo(name)
            member.size = len(content)
            archive.addfile(member, BytesIO(content))
    stream.seek(0)
    return stream


def malformed_name_source(archive_type):
    if archive_type == "zip":
        content = bytearray(zip_source([("a.c", b"source")]).getvalue())
        central = content.index(b"PK\x01\x02")
        for flags, name in ((6, 30), (central + 8, central + 46)):
            content[flags:flags + 2] = (int.from_bytes(content[flags:flags + 2], "little") | 0x800).to_bytes(
                2, "little",
            )
            content[name] = 0xff
    else:
        content = bytearray(tar_source([("a.c", b"source")]).getvalue())
        content[0] = 0xff
        content[148:156] = b"        "
        content[148:156] = f"{sum(content[:512]):06o}\0 ".encode("ascii")
    return BytesIO(content)


@pytest.mark.parametrize("archive_type", ["zip", "tar"])
def test_malformed_archive_names_raise_validation_errors(archive_type):
    with pytest.raises(ValueError):
        validate_reference(malformed_name_source(archive_type), f"source.{archive_type}")


@pytest.mark.parametrize("name,stream", [
    ("source.zip", lambda: zip_source([("repo/a.py", b"first\nneedle\nlast\n")])),
    ("source.tar", lambda: tar_source([("repo/a.py", b"first\nneedle\nlast\n")])),
    ("source.tar.gz", lambda: tar_source([("repo/a.py", b"first\nneedle\nlast\n")], "w:gz")),
    ("source.tgz", lambda: tar_source([("repo/a.py", b"first\nneedle\nlast\n")], "w:gz")),
])
def test_archive_listing_reading_and_search(name, stream):
    source = stream()
    validate_reference(source, name)
    assert source.tell() == 0
    with CodebaseReference(source, name) as reference:
        assert reference.list_files()["files"] == [{"path": "repo/a.py", "size": 18}]
        assert reference.read_lines("repo/a.py", 2, 1) == {
            "path": "repo/a.py", "start_line": 2, "end_line": 2,
            "content": "needle\n", "total_lines": 3, "next_line": 3,
        }
        assert reference.read_lines("repo/a.py", 3)["next_line"] is None
        assert reference.search("needle")["matches"] == [
            {"path": "repo/a.py", "line": 2, "text": "needle"},
        ]


def test_standalone_file_bom_and_missing_member():
    with CodebaseReference(BytesIO(b"\xef\xbb\xbfhello\n"), "a.txt") as reference:
        assert reference.read_lines("a.txt")["content"] == "hello\n"
        with pytest.raises(LookupError, match="not found"):
            reference.read_lines("/etc/passwd")


def test_listing_pagination_and_patterns():
    with CodebaseReference(zip_source([("b.c", b""), ("a.c", b""), ("x.py", b"")]), "s.zip") as ref:
        first = ref.list_files("*.c", limit=1)
        assert first == {"files": [{"path": "a.c", "size": 0}], "total": 2, "next_offset": 1}
        assert ref.list_files("*.c", offset=1, limit=1)["next_offset"] is None
        assert ref.list_files("missing*")["total"] == 0


def test_search_limits_binary_and_encoding_skips():
    source = zip_source([
        ("a.c", b"needle\nneedle again\n"),
        ("b.bin", b"\x00needle"),
        ("c.txt", b"\xffneedle"),
    ])
    with CodebaseReference(source, "s.zip") as ref:
        assert ref.search("needle", max_results=1)["truncated"] is True
        assert ref.search("needle") == {
            "matches": [{"path": "a.c", "line": 1, "text": "needle"},
                        {"path": "a.c", "line": 2, "text": "needle again"}],
            "truncated": False, "searched_files": 1, "skipped_binary_files": 2,
        }
        assert ref.search("NEEDLE")["matches"] == []
        with pytest.raises(ValueError, match="binary"):
            ref.read_lines("b.bin")
        with pytest.raises(ValueError, match="UTF-8"):
            ref.read_lines("c.txt")


@pytest.mark.parametrize("path", ["../bad", "/etc/passwd", "a/../../bad", r"a\bad", "C:/bad", "a\nbad"])
@pytest.mark.parametrize("archive", ["zip", "tar"])
def test_unsafe_paths_rejected(path, archive):
    stream = zip_source([(path, b"x")]) if archive == "zip" else tar_source([(path, b"x")])
    with pytest.raises(ValueError, match="unsafe path"):
        validate_reference(stream, f"source.{archive}")


def test_duplicate_paths_rejected():
    with pytest.warns(UserWarning):
        stream = zip_source([("a", b"x"), ("a", b"x")])
    with pytest.raises(ValueError, match="duplicate"):
        validate_reference(stream, "s.zip")
    with pytest.raises(ValueError, match="duplicate"):
        validate_reference(tar_source([("a", b"x"), ("./a", b"x")]), "s.tar")


def test_tar_root_and_subdirectory_markers_are_supported():
    stream = BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for name in (".", "./repo"):
            directory = tarfile.TarInfo(name)
            directory.type = tarfile.DIRTYPE
            archive.addfile(directory)
        member = tarfile.TarInfo("./repo/main.c")
        member.size = 1
        archive.addfile(member, BytesIO(b"x"))
    validate_reference(stream, "source.tgz")
    with CodebaseReference(stream, "source.tgz") as ref:
        assert ref.list_files()["files"] == [{"path": "repo/main.c", "size": 1}]
        assert ref.read_lines("repo/main.c")["content"] == "x"


@pytest.mark.parametrize("archive_type", ["zip", "tar"])
def test_symlinks_rejected(archive_type):
    stream = BytesIO()
    if archive_type == "zip":
        with zipfile.ZipFile(stream, "w") as archive:
            member = zipfile.ZipInfo("link")
            member.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(member, "/etc/passwd")
    else:
        with tarfile.open(fileobj=stream, mode="w") as archive:
            member = tarfile.TarInfo("link")
            member.type = tarfile.SYMTYPE
            member.linkname = "/etc/passwd"
            archive.addfile(member)
    with pytest.raises(ValueError, match="[Ll]inks"):
        validate_reference(stream, f"s.{archive_type}")


@pytest.mark.parametrize("name", ["s.zip", "s.tar", "s.tar.gz"])
def test_corrupt_archives_return_explicit_errors(name):
    with pytest.raises(ValueError, match="Invalid"):
        validate_reference(BytesIO(b"not an archive"), name)


def test_empty_archive_rejected():
    with pytest.raises(ValueError, match="no files"):
        validate_reference(zip_source([]), "s.zip")


def test_archive_entry_member_and_expansion_limits(monkeypatch):
    import src.helpers.codebase_reference as module
    monkeypatch.setattr(module, "MAX_ENTRIES", 1)
    with pytest.raises(ValueError, match="5000"):
        validate_reference(zip_source([("a", b"x"), ("b", b"x")]), "s.zip")
    monkeypatch.setattr(module, "MAX_ENTRIES", 5000)


def test_large_plain_files_remain_readable_without_archive_limits(monkeypatch):
    import src.helpers.codebase_reference as module
    monkeypatch.setattr(module, "MAX_FILE_BYTES", 8)
    monkeypatch.setattr(module, "MAX_EXPANDED_BYTES", 12)
    source = BytesIO(b"first line\nneedle line\n")
    validate_reference(source, "over-limit.c")
    source.seek(0)
    with CodebaseReference(source, "over-limit.c") as ref:
        assert ref.read_lines("over-limit.c", 2, 1)["content"] == "needle line\n"
        assert ref.search("needle")["matches"] == [
            {"path": "over-limit.c", "line": 2, "text": "needle line"},
        ]


def test_large_archive_members_are_rejected():
    with pytest.raises(ValueError, match="invalid file size"):
        validate_reference(zip_source([("too-big.c", b"x" * (10 * 1024 * 1024 + 1))]), "over-limit.zip")


def test_real_archive_entry_count_boundary():
    entries = [(f"source-{index}.c", b"") for index in range(5000)]
    with CodebaseReference(zip_source(entries), "at-limit.zip") as reference:
        assert len(reference.entries) == 5000
    entries.append(("extra.c", b""))
    with pytest.raises(ValueError, match="5000"):
        validate_reference(zip_source(entries), "over-limit.zip")


def test_zip_checksum_failure_is_rejected():
    source = BytesIO()
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("main.c", b"original-source")
    content = bytearray(source.getvalue())
    content[content.index(b"original-source")] = ord("X")
    with pytest.raises(ValueError, match="could not be read"):
        validate_reference(BytesIO(content), "corrupt.zip")


def test_read_response_byte_limit_and_long_lines(monkeypatch):
    import src.helpers.codebase_reference as module
    monkeypatch.setattr(module, "MAX_RESPONSE_BYTES", 4)
    with CodebaseReference(BytesIO(b"a\nb\nc\n"), "a.txt") as ref:
        assert ref.read_lines("a.txt")["content"] == "a\nb\n"
        assert ref.read_lines("a.txt")["next_line"] == 3
    with CodebaseReference(BytesIO(b"12345\n"), "a.txt") as ref:
        with pytest.raises(ValueError, match="line exceeds"):
            ref.read_lines("a.txt")
