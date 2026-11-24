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


@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("effective_uid", [0, 1000])
@pytest.mark.parametrize("cache_ids", [(1234, 5678), (0, 0)], ids=["mapped-host", "rootless"])
def test_provision_inherits_corrected_cache_ownership_only_for_new_root_created_directories(
    tmp_path, monkeypatch, existing, effective_uid, cache_ids,
):
    from types import SimpleNamespace

    name = directory_name("project", "variant")
    root = tmp_path / name
    if existing:
        root.mkdir()
    cache_inode = tmp_path.stat().st_ino
    fstat = os.fstat
    changes = []

    def cache_owner(fd):
        info = fstat(fd)
        if info.st_ino == cache_inode:
            return SimpleNamespace(st_uid=cache_ids[0], st_gid=cache_ids[1])
        return info

    monkeypatch.setattr(module.os, "geteuid", lambda: effective_uid)
    monkeypatch.setattr(module.os, "fstat", cache_owner)
    monkeypatch.setattr(module.os, "fchown", lambda fd, uid, gid: changes.append((fstat(fd).st_ino, uid, gid)))

    provision_directory(str(tmp_path), name)

    assert root.is_dir()
    assert changes == ([(root.stat().st_ino, *cache_ids)] if effective_uid == 0 and not existing else [])


def test_list_and_read_with_pagination(tree):
    cache, name, root = tree
    (root / "z.c").write_text("needle again\n")
    with CodebaseDirectory(str(cache), name) as ref:
        assert ref.list_files("*.c", limit=1) == {
            "files": [{"path": "src/main.c", "size": 18}], "total": 2, "next_offset": 1,
        }
        assert ref.read_lines("src/main.c", 2, 1)["content"] == "needle\n"
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
        for path, error in (("binary", "binary"), ("latin", "UTF-8")):
            with pytest.raises(ValueError, match=error):
                ref.read_lines(path)
        monkeypatch.setattr(module, "MAX_FILE_BYTES", 8)
        with pytest.raises(ValueError, match="maximum readable"):
            ref.read_lines("src/main.c")
    monkeypatch.setattr(module, "MAX_ENTRIES", 1)
    with pytest.raises(ValueError, match="entry browsing limit"):
        with CodebaseDirectory(str(cache), name):
            pass


def test_search_validates_current_file_and_directory_scope(tree, monkeypatch):
    from src.helpers import host_mount_helper as hh

    cache, name, root = tree
    path = root / "log"
    query = "\u20ac.log"
    path.write_text("x" * (hh.SEARCH_CHUNK - 1) + query + "\n" + query)
    monkeypatch.setattr(hh, "SEARCH_BYTES", hh.SEARCH_CHUNK)
    with CodebaseDirectory(str(cache), name, index=False) as ref:
        first = ref.search_file("v", "log", query, "")
        assert not first["complete"] and not first["matches"]
        cursor = first["next_cursor"]
        with pytest.raises(hh.HelperError, match="cursor"):
            ref.search_file("other", "log", query, cursor)
        second = ref.search_file("v", "log", query, cursor)
        assert second["complete"] and [m["line"] for m in second["matches"]] == [1, 2]
        original = os.pread

        def mutate(*args):
            data = original(*args)
            path.write_text("new log")
            return data

        monkeypatch.setattr(os, "pread", mutate)
        with pytest.raises(hh.HelperError, match="changed"):
            ref.search_file("v", "log", query, cursor)


@pytest.mark.parametrize("count", [500_000, 500_001])
def test_directory_entry_count_boundary(tree, monkeypatch, count):
    from contextlib import contextmanager
    from types import SimpleNamespace
    import stat

    cache, name, _ = tree
    info = SimpleNamespace(st_mode=stat.S_IFREG, st_nlink=1, st_size=0)

    @contextmanager
    def scandir(_fd):
        yield (SimpleNamespace(name=f"source-{index:06d}.c", stat=lambda **kwargs: info) for index in range(count))

    monkeypatch.setattr(module.os, "scandir", scandir)
    if count > 500_000:
        with pytest.raises(ValueError, match="500000-entry browsing limit"):
            with CodebaseDirectory(str(cache), name):
                pass
    else:
        with CodebaseDirectory(str(cache), name) as reference:
            assert len(reference.entries) == count
            assert reference.list_files(offset=499_999) == {
                "files": [{"path": "source-499999.c", "size": 0}], "total": count, "next_offset": None,
            }


def test_fifo_replacement_after_index_is_rejected_without_blocking(tree):
    cache, name, root = tree
    with CodebaseDirectory(str(cache), name) as ref:
        (root / "src" / "main.c").unlink()
        os.mkfifo(root / "src" / "main.c")
        with pytest.raises(ValueError, match="special"):
            ref.read_lines("src/main.c")
