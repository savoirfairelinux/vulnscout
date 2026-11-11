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


import shutil
import subprocess
import zipfile as _zipfile
from io import BytesIO as _BytesIO
from unittest.mock import patch as _patch

from src.helpers.codebase_reference import CodebaseReference as _Reference

needs_pdftotext = pytest.mark.skipif(shutil.which("pdftotext") is None, reason="pdftotext not installed")


def make_pdf(pages):
    """A minimal valid PDF with one Helvetica text line per page."""
    objects = ["<< /Type /Catalog /Pages 2 0 R >>", None,
               "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    kids = []
    for text in pages:
        stream = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET"
        objects.append(f"<< /Length {len(stream)} >>\nstream\n{stream}\nendstream")
        objects.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                       f"/Resources << /Font << /F1 3 0 R >> >> /Contents {len(objects)} 0 R >>")
        kids.append(f"{len(objects)} 0 R")
    objects[1] = f"<< /Type /Pages /Kids [{' '.join(kids)}] /Count {len(kids)} >>"
    out, offsets = b"%PDF-1.4\n", []
    for number, body in enumerate(objects, 1):
        offsets.append(len(out))
        out += f"{number} 0 obj\n{body}\nendobj\n".encode()
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    out += "".join(f"{offset:010d} 00000 n \n" for offset in offsets).encode()
    out += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return out


@needs_pdftotext
def test_pdf_pages_are_marked_read_and_searched():
    with _Reference(_BytesIO(make_pdf(["Gateway overview", "CSRF on admin UI"])), "report.pdf") as reference:
        text = reference.text("report.pdf")
        read = reference.read_lines("report.pdf", 1, 200)
        found = reference.search("CSRF")
    assert text.startswith("--- page 1 ---\n") and "--- page 2 ---\n" in text
    assert "Gateway overview" in read["content"]
    assert found["matches"][0]["path"] == "report.pdf"
    assert found["matches"][0]["line"] > 2 and found["skipped_binary_files"] == 0


@needs_pdftotext
def test_pdf_inside_a_zip_is_readable():
    archive = _BytesIO()
    with _zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("docs/report.pdf", make_pdf(["Inside zip"]))
    with _Reference(archive, "bundle.zip") as reference:
        text = reference.text("docs/report.pdf")
    assert text.startswith("--- page 1 ---\n") and "Inside zip" in text


@needs_pdftotext
def test_pdf_without_text_and_garbage_pdf_are_errors():
    with _Reference(_BytesIO(make_pdf([""])), "scan.pdf") as reference:
        with pytest.raises(ValueError, match="no extractable text"):
            reference.text("scan.pdf")
    with _Reference(_BytesIO(b"%PDF-1.4 garbage"), "bad.pdf") as reference:
        with pytest.raises(ValueError, match="could not be read"):
            reference.text("bad.pdf")
        assert reference.search("x")["skipped_binary_files"] == 1


@pytest.mark.parametrize("outcome,message", [
    (subprocess.CompletedProcess([], 1, b"", b"Command Line Error: Incorrect password\n"), "encrypted"),
    (subprocess.TimeoutExpired("pdftotext", 30), "timed out"),
    (FileNotFoundError("pdftotext"), "unavailable"),
])
def test_pdf_failures_are_value_errors(outcome, message):
    effect = {"side_effect": outcome} if isinstance(outcome, BaseException) else {"return_value": outcome}
    with _patch("src.helpers.codebase_reference.subprocess.run", **effect):
        with _Reference(_BytesIO(b"%PDF-1.4"), "locked.pdf") as reference:
            with pytest.raises(ValueError, match=message):
                reference.text("locked.pdf")


def test_pdf_text_is_capped():
    from src.helpers import codebase_reference

    big = subprocess.CompletedProcess([], 0, b"a" * 100 + b"\f", b"")
    with _patch("src.helpers.codebase_reference.subprocess.run", return_value=big), \
            _patch.object(codebase_reference, "PDF_TEXT_LIMIT", 50):
        assert len(codebase_reference._pdf_text(b"%PDF").encode()) == 50
