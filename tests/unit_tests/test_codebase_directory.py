import os

import pytest

from src.helpers import codebase_directory as module
from src.helpers.codebase_directory import CodebaseDirectory, directory_name, provision_directory


@pytest.fixture
def tree(tmp_path):
    name = directory_name("project", "variant")
    provision_directory(str(tmp_path), name)
    root = tmp_path / name
    (root / "src").mkdir()
    (root / "src" / "main.c").write_text("first\nneedle\nlast\n")
    return tmp_path, name, root


def test_directory_names_are_portable_sanitized_and_bounded():
    assert directory_name("demo", "dfdfdf") == "context-demo-dfdfdf"
    assert directory_name("../../a/b", " ! ") == "context-a-b-unnamed"
    assert directory_name("a/b", "v") == directory_name("a.b", "v")
    assert len(directory_name("x" * 1000, "y" * 1000)) < 255
    with pytest.raises(ValueError, match="Invalid"):
        module.directory_path("/cache", "../outside")


def test_list_read_and_search_with_pagination(tree):
    cache, name, root = tree
    (root / "z.c").write_text("needle again\n")
    with CodebaseDirectory(str(cache), name) as ref:
        assert ref.list_files("*.c", limit=1) == {
            "files": [{"path": "src/main.c", "size": 18}], "total": 2, "next_offset": 1,
        }
        assert ref.read_lines("src/main.c", 2, 1)["content"] == "needle\n"
        assert ref.search("needle", max_results=1)["truncated"] is True
        assert len(ref.search("needle")["matches"]) == 2
        for path in ("../outside", "/etc/passwd", "src/../../outside"):
            with pytest.raises(LookupError):
                ref.read_lines(path)


def test_sensitive_names_links_and_special_files_are_never_exposed(tree, tmp_path):
    cache, name, root = tree
    outside = tmp_path / "outside"
    outside.write_text("private needle")
    for filename in (".env", ".env.production", "credentials.json", "server.key", "id_rsa",
                     "passwords.txt", "api-token.txt", "secret.yaml", "db.sqlite", "backup.bak",
                     "id_ecdsa", "id_dsa", "kubeconfig"):
        (root / filename).write_text("private needle")
    (root / ".git").mkdir()
    (root / ".git" / "config").write_text("private needle")
    (root / "link").symlink_to(outside)
    (root / "linked-dir").symlink_to(tmp_path, target_is_directory=True)
    os.link(outside, root / "hardlink")
    os.mkfifo(root / "fifo")
    with CodebaseDirectory(str(cache), name) as ref:
        assert [row["path"] for row in ref.list_files()["files"]] == ["src/main.c"]
        assert ref.search("private")["matches"] == []
        with pytest.raises(LookupError):
            ref.read_lines(".env")


@pytest.mark.parametrize("target", ["file", "parent"])
def test_symlink_replacement_after_index_cannot_escape(tree, tmp_path, target):
    cache, name, root = tree
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "main.c").write_text("private")
    with CodebaseDirectory(str(cache), name) as ref:
        if target == "file":
            (root / "src" / "main.c").unlink()
            (root / "src" / "main.c").symlink_to(outside / "main.c")
        else:
            (root / "src").rename(root / "old")
            (root / "src").symlink_to(outside, target_is_directory=True)
        with pytest.raises(OSError):
            ref.read_lines("src/main.c")


def test_root_symlinks_are_rejected_for_provision_and_browse(tmp_path):
    name = directory_name("p", "v")
    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / name).symlink_to(outside, target_is_directory=True)
    with pytest.raises(OSError):
        provision_directory(str(tmp_path), name)
    with pytest.raises(OSError):
        with CodebaseDirectory(str(tmp_path), name):
            pass


def test_missing_empty_and_unreadable_directories_report_errors(tree):
    cache, name, root = tree
    with pytest.raises(FileNotFoundError):
        with CodebaseDirectory(str(cache / "missing"), name):
            pass
    (root / "src" / "main.c").unlink()
    with pytest.raises(ValueError, match="empty"):
        with CodebaseDirectory(str(cache), name):
            pass
    if os.getuid() != 0:
        root.chmod(0)
        try:
            with pytest.raises(PermissionError):
                with CodebaseDirectory(str(cache), name):
                    pass
        finally:
            root.chmod(0o750)


def test_directory_limits_binary_and_encoding_errors(tree, monkeypatch):
    cache, name, root = tree
    (root / "binary").write_bytes(b"\0needle")
    (root / "latin").write_bytes(b"\xff")
    with CodebaseDirectory(str(cache), name) as ref:
        assert ref.search("needle")["skipped_binary_files"] == 2
        for path, error in (("binary", "binary"), ("latin", "UTF-8")):
            with pytest.raises(ValueError, match=error):
                ref.read_lines(path)
        monkeypatch.setattr(module, "MAX_FILE_BYTES", 8)
        with pytest.raises(ValueError, match="maximum readable"):
            ref.read_lines("src/main.c")
        monkeypatch.setattr(module, "MAX_EXPANDED_BYTES", 8)
        with pytest.raises(ValueError, match="search budget"):
            ref.search("needle")
    monkeypatch.setattr(module, "MAX_ENTRIES", 1)
    with pytest.raises(ValueError, match="entry browsing limit"):
        with CodebaseDirectory(str(cache), name):
            pass


def test_search_budget_handles_files_growing_after_index(tree, monkeypatch):
    cache, name, root = tree
    (root / "z.c").write_text("x")
    monkeypatch.setattr(module, "MAX_EXPANDED_BYTES", 20)
    with CodebaseDirectory(str(cache), name) as ref:
        (root / "z.c").write_text("x" * 10)
        with pytest.raises(ValueError, match="search budget"):
            ref.search("missing")
        assert ref.read_lines("z.c")["content"] == "x" * 10


def test_fifo_replacement_after_index_is_rejected_without_blocking(tree):
    cache, name, root = tree
    with CodebaseDirectory(str(cache), name) as ref:
        (root / "src" / "main.c").unlink()
        os.mkfifo(root / "src" / "main.c")
        with pytest.raises(ValueError, match="special"):
            ref.read_lines("src/main.c")


def test_search_accounts_for_reads_rejected_after_concurrent_growth(tree, monkeypatch):
    from types import SimpleNamespace
    cache, name, root = tree
    (root / "src" / "main.c").write_text("x")
    (root / "z.c").write_text("x")
    monkeypatch.setattr(module, "MAX_FILE_BYTES", 2)
    monkeypatch.setattr(module, "MAX_EXPANDED_BYTES", 4)
    with CodebaseDirectory(str(cache), name) as ref:
        (root / "src" / "main.c").write_text("xxx")
        (root / "z.c").write_text("xxx")
        fstat = os.fstat

        def stat_before_growth(fd):
            info = fstat(fd)
            return SimpleNamespace(st_mode=info.st_mode, st_nlink=info.st_nlink, st_size=1)

        monkeypatch.setattr(module.os, "fstat", stat_before_growth)
        with pytest.raises(ValueError, match="search budget"):
            ref.search("missing")
