# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for _PriorityWriteLock and setup_write_serialization in extensions.py.

Validates that:
  - The priority write lock serialises concurrent writers.
  - Flask threads (priority 0) are woken before EPSS (1) before NVD (2).
  - SQLAlchemy session events correctly acquire/release the lock.
  - The lock survives session destruction between test fixtures.
  - The lock is released whenever the outermost transaction ends, even when
    it ends without a commit/rollback event (close after an error, failed
    COMMIT), and waiting for it is bounded by a timeout.
"""

import logging
import os
import time
import threading
import pytest
from sqlalchemy import event
from sqlalchemy.exc import IntegrityError, OperationalError

from src.extensions import (
    DEFAULT_WRITE_LOCK_TIMEOUT, WriteLockTimeout, _PriorityWriteLock, _db_write_lock,
    _write_lock_state, hold_write_lock, write_lock, write_lock_timeout,
)
from src.extensions import db as _db


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def app():
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        from src.bin.webapp import create_app
        application = create_app()
        application.config.update({"TESTING": True, "SCAN_FILE": "/dev/null"})
        with application.app_context():
            _db.create_all()
            yield application
            _db.drop_all()
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture(autouse=True)
def _release_global_lock():
    """Safety net: ensure the global write-lock is never left held between tests."""
    yield
    # Force-release if still held (prevents cascading deadlocks on failure).
    with _db_write_lock._mutex:
        _db_write_lock._held = False
        _db_write_lock._owner = None
        _db_write_lock._waiters = []
    _write_lock_state.__dict__.pop("held", None)


@pytest.fixture()
def lock():
    """A fresh _PriorityWriteLock for each test (not the global one)."""
    return _PriorityWriteLock()


# ===================================================================
# _PriorityWriteLock — pure unit tests
# ===================================================================

class TestPriorityWriteLock:

    # ---- thread-name → priority mapping ----------------------------

    def test_flask_thread_priority(self):
        """Default / Werkzeug threads get priority 0 (highest)."""
        assert _PriorityWriteLock._thread_priority() == 0

    def test_epss_thread_priority(self):
        result = []

        def check():
            result.append(_PriorityWriteLock._thread_priority())

        t = threading.Thread(target=check, name="enrichment-epss")
        t.start()
        t.join()
        assert result[0] == 1

    def test_nvd_thread_priority(self):
        result = []

        def check():
            result.append(_PriorityWriteLock._thread_priority())

        t = threading.Thread(target=check, name="enrichment-nvd")
        t.start()
        t.join()
        assert result[0] == 2

    # ---- basic acquire / release -----------------------------------

    def test_acquire_release(self, lock):
        """Acquire then release should not deadlock."""
        lock.acquire()
        assert lock._held
        lock.release()
        assert not lock._held

    def test_double_release_is_safe(self, lock):
        """Releasing an un-held lock is a no-op."""
        lock.release()                  # not held — no-op
        lock.acquire()
        lock.release()
        lock.release()                  # already released — no-op
        assert not lock._held

    def test_second_acquire_blocks_until_release(self, lock):
        """A second acquire blocks until the first holder releases."""
        lock.acquire()
        acquired = threading.Event()

        def waiter():
            lock.acquire()
            acquired.set()
            lock.release()

        t = threading.Thread(target=waiter)
        t.start()
        # The waiter should be blocked
        assert not acquired.wait(timeout=0.15)
        # Release from the main thread — waiter should proceed
        lock.release()
        assert acquired.wait(timeout=2)
        t.join()

    # ---- priority ordering -----------------------------------------

    def test_priority_ordering(self, lock):
        """When multiple threads wait, highest priority (lowest value) wins.

        Scenario:
          1. Main thread holds the lock.
          2. Three threads with different priorities try to acquire.
          3. After release, they should proceed in priority order:
             Flask (0) → EPSS (1) → NVD (2).
        """
        lock.acquire()                  # main thread holds the lock

        order = []
        barrier = threading.Barrier(3)  # all waiters line up before competing

        def waiter(label, thread_name):
            t = threading.current_thread()
            old_name = t.name
            t.name = thread_name
            try:
                barrier.wait(timeout=5)    # synchronise start
                lock.acquire()             # block here until released
                order.append(label)
                lock.release()
            finally:
                t.name = old_name

        threads = [
            threading.Thread(target=waiter, args=("nvd", "enrichment-nvd")),
            threading.Thread(target=waiter, args=("epss", "enrichment-epss")),
            threading.Thread(target=waiter, args=("flask", "werkzeug-thread")),
        ]
        for t in threads:
            t.start()

        # Give waiters time to all reach acquire() and register
        time.sleep(0.3)

        # Release — the priority queue should wake Flask, then EPSS, then NVD
        lock.release()
        for t in threads:
            t.join(timeout=5)

        assert order == ["flask", "epss", "nvd"], f"Got: {order}"

    def test_same_priority_fifo(self, lock):
        """Threads with the same priority are served in arrival order (FIFO)
        because Python's sort is stable.
        """
        lock.acquire()
        order = []
        barrier = threading.Barrier(3)

        def waiter(idx):
            barrier.wait(timeout=5)
            lock.acquire()
            order.append(idx)
            lock.release()

        threads = []
        for i in range(3):
            t = threading.Thread(target=waiter, args=(i,), name=f"flask-{i}")
            threads.append(t)
            t.start()

        # Let all threads reach barrier.wait then acquire()
        time.sleep(0.3)

        lock.release()    # start servicing
        for t in threads:
            t.join(timeout=5)

        # All 3 should eventually run
        assert sorted(order) == [0, 1, 2]


# ===================================================================
# setup_write_serialization — integration with SQLAlchemy session
# ===================================================================

class TestWriteSerializationEvents:
    """Verify that the session events acquire/release the write lock correctly.

    Uses the global ``_db_write_lock._held`` flag and the thread-local
    ``_write_lock_state.held`` to verify lock state.
    """

    def test_lock_acquired_on_dirty_flush(self, app):
        """Flushing dirty data acquires the write lock."""
        from src.models.project import Project
        assert not _db_write_lock._held

        p = Project(name="LockTest")
        _db.session.add(p)
        _db.session.flush()
        assert _db_write_lock._held, \
            "Write lock should be held after flushing dirty data"
        assert getattr(_write_lock_state, "held", False)

        _db.session.commit()
        assert not _db_write_lock._held, \
            "Write lock should be released after commit"
        assert not getattr(_write_lock_state, "held", False)

    def test_lock_released_on_rollback(self, app):
        """Rolling back a dirty session releases the write lock."""
        from src.models.project import Project
        p = Project(name="RollbackTest")
        _db.session.add(p)
        _db.session.flush()
        assert _db_write_lock._held

        _db.session.rollback()
        assert not _db_write_lock._held, \
            "Write lock should be released after rollback"

    def test_no_lock_on_clean_flush(self, app):
        """Flushing when there are no pending changes should not acquire lock."""
        _db.session.flush()          # nothing dirty
        assert not _db_write_lock._held

    def test_lock_not_reacquired_on_second_flush(self, app):
        """Subsequent flushes within the same transaction don't deadlock."""
        from src.models.project import Project
        _db.session.add(Project(name="First"))
        _db.session.flush()
        assert _db_write_lock._held

        _db.session.add(Project(name="Second"))
        _db.session.flush()     # must NOT deadlock (re-entrant flush)
        assert _db_write_lock._held

        _db.session.commit()
        assert not _db_write_lock._held

    def test_batch_session_acquires_and_releases(self, app):
        """batch_session() holds the lock during the block, releases on exit."""
        from src.extensions import batch_session
        from src.models.project import Project

        with batch_session():
            _db.session.add(Project(name="Batch1"))
            _db.session.commit()     # _deferred_commit → flush only
            assert _db_write_lock._held, \
                "Lock should be held inside batch_session after deferred commit"

        # After the block, original_commit() ran → lock released
        assert not _db_write_lock._held, \
            "Lock should be released after batch_session exits"

    def test_batch_session_releases_on_error(self, app):
        """If batch_session throws, the lock is still released via rollback."""
        from src.extensions import batch_session
        from src.models.project import Project

        with pytest.raises(ValueError):
            with batch_session():
                _db.session.add(Project(name="ErrTest"))
                _db.session.commit()     # deferred → flush
                assert _db_write_lock._held
                raise ValueError("simulated failure")

        assert not _db_write_lock._held, \
            "Lock should be released after exception in batch_session"

    def test_lock_survives_session_destruction(self, app):
        """Thread-local flag prevents deadlock when Session objects change.

        begin_nested() acquires the lock on flush.  Releasing the savepoint
        does not end the outer transaction, so the lock is kept until the
        outer commit; a subsequent begin_nested() must not deadlock.
        """
        from src.models.project import Project

        # Simulate a begin_nested write (like PackagesController.add)
        with _db.session.begin_nested():
            _db.session.add(Project(name="Nested"))
        assert _db_write_lock._held

        # Another begin_nested in the same thread should work fine.
        with _db.session.begin_nested():
            _db.session.add(Project(name="Nested2"))
        assert _db_write_lock._held

        # Explicit commit on the outer transaction.
        _db.session.commit()
        assert not _db_write_lock._held

    def test_savepoint_commit_keeps_outer_lock(self, app):
        """Committing a savepoint must not release the outer transaction's lock."""
        from src.models.project import Project
        _db.session.add(Project(name="Outer"))
        _db.session.flush()
        assert _db_write_lock._held

        with _db.session.begin_nested():
            _db.session.add(Project(name="Inner"))
            _db.session.flush()
        assert _db_write_lock._held
        assert getattr(_write_lock_state, "held", False)

        _db.session.commit()
        assert not _db_write_lock._held

    def test_savepoint_rollback_keeps_outer_lock(self, app):
        """Rolling back a savepoint (explicitly or after a failed flush) keeps the lock."""
        from src.models.project import Project
        _db.session.add(Project(name="Dup"))
        _db.session.commit()

        _db.session.add(Project(name="Outer"))
        _db.session.flush()
        assert _db_write_lock._held

        nested = _db.session.begin_nested()
        _db.session.add(Project(name="Inner"))
        _db.session.flush()
        nested.rollback()
        assert _db_write_lock._held

        with pytest.raises(IntegrityError):
            with _db.session.begin_nested():
                _db.session.add(Project(name="Dup"))
        assert _db_write_lock._held

        _db.session.rollback()
        assert not _db_write_lock._held
        assert not getattr(_write_lock_state, "held", False)

    def test_failed_root_flush_releases_lock(self, app):
        """A failed flush rolls back the root transaction and releases the lock."""
        from src.models.project import Project
        _db.session.add(Project(name="Dup"))
        _db.session.commit()

        _db.session.add(Project(name="Dup"))
        with pytest.raises(IntegrityError):
            _db.session.flush()
        assert not _db_write_lock._held
        _db.session.rollback()
        assert not _db_write_lock._held

    def test_close_releases_lock(self, app):
        """Closing a session with flushed, uncommitted writes releases the lock."""
        from src.models.project import Project
        _db.session.add(Project(name="Closed"))
        _db.session.flush()
        assert _db_write_lock._held

        _db.session.close()
        assert not _db_write_lock._held
        assert not getattr(_write_lock_state, "held", False)

    def test_hold_write_lock_released_by_close(self, app):
        """hold_write_lock() is released when the session transaction ends."""
        _db.session.execute(_db.text("SELECT 1"))
        hold_write_lock()
        assert _db_write_lock._held
        _db.session.close()
        assert not _db_write_lock._held

    def test_write_lock_releases_on_exit(self, app):
        with write_lock():
            assert _db_write_lock._held
        assert not _db_write_lock._held
        assert not getattr(_write_lock_state, "held", False)


# ===================================================================
# Priority works end-to-end with DB writes
# ===================================================================

class TestPriorityEndToEnd:
    """Verify that a simulated enrichment thread yields priority to Flask."""

    def test_flask_preempts_nvd(self, app):
        """When NVD and Flask both wait, Flask always goes first.

        Steps:
          1. Main thread holds the lock via flush.
          2. NVD thread and Flask thread both try to flush.
          3. Main releases → Flask must proceed before NVD.
        """
        from src.models.project import Project

        order = []
        all_registered = threading.Event()

        def nvd_writer():
            with app.app_context():
                _db.session.add(Project(name="NVD-proj"))
                all_registered.wait(timeout=5)
                _db.session.flush()
                order.append("nvd")
                _db.session.commit()

        def flask_writer():
            with app.app_context():
                _db.session.add(Project(name="Flask-proj"))
                all_registered.wait(timeout=5)
                _db.session.flush()
                order.append("flask")
                _db.session.commit()

        # Hold the lock so both writers must queue
        _db.session.add(Project(name="Holder"))
        _db.session.flush()
        assert _db_write_lock._held

        t_nvd = threading.Thread(target=nvd_writer, name="enrichment-nvd")
        t_flask = threading.Thread(target=flask_writer, name="flask-handler")

        t_nvd.start()
        t_flask.start()

        # Let both threads reach add + wait on all_registered
        time.sleep(0.1)
        all_registered.set()
        # Let both threads call flush → block on _db_write_lock.acquire()
        time.sleep(0.3)

        # Release — Flask (priority 0) should go before NVD (priority 2)
        _db.session.commit()
        t_flask.join(timeout=5)
        t_nvd.join(timeout=5)

        assert len(order) == 2, f"Not all writers completed: {order}"
        assert order[0] == "flask", f"Expected flask first, got: {order}"


# ===================================================================
# Bounded wait
# ===================================================================

class TestWriteLockTimeout:

    @pytest.mark.parametrize("raw, expected", [
        (None, DEFAULT_WRITE_LOCK_TIMEOUT),
        ("", DEFAULT_WRITE_LOCK_TIMEOUT),
        ("12.5", 12.5),
        ("0", None),
        ("-1", None),
        ("soon", DEFAULT_WRITE_LOCK_TIMEOUT),
        ("nan", DEFAULT_WRITE_LOCK_TIMEOUT),
        ("inf", DEFAULT_WRITE_LOCK_TIMEOUT),
        (str(threading.TIMEOUT_MAX * 2), DEFAULT_WRITE_LOCK_TIMEOUT),
    ])
    def test_timeout_from_environment(self, monkeypatch, raw, expected):
        if raw is None:
            monkeypatch.delenv("VULNSCOUT_DB_WRITE_LOCK_TIMEOUT", raising=False)
        else:
            monkeypatch.setenv("VULNSCOUT_DB_WRITE_LOCK_TIMEOUT", raw)
        assert write_lock_timeout() == expected

    @pytest.mark.parametrize("raw, timeout", [
        ("inf", None),
        ("nan", None),
        (str(threading.TIMEOUT_MAX * 2), None),
        ("1", float("inf")),
        ("1", float("nan")),
        ("1", threading.TIMEOUT_MAX * 2),
    ])
    def test_invalid_timeout_does_not_strand_contended_lock(self, lock, monkeypatch, raw, timeout):
        monkeypatch.setenv("VULNSCOUT_DB_WRITE_LOCK_TIMEOUT", raw)
        lock.acquire()
        acquired = threading.Event()
        errors = []

        def waiter():
            try:
                lock.acquire(timeout=timeout)
                acquired.set()
                lock.release()
            except Exception as exc:
                errors.append(exc)

        t = threading.Thread(target=waiter, name="invalid-timeout-waiter")
        t.start()
        deadline = time.monotonic() + 5
        while not lock._waiters and t.is_alive() and time.monotonic() < deadline:
            time.sleep(0.01)
        queued = bool(lock._waiters)
        lock.release()
        t.join(timeout=5)

        assert queued
        assert not t.is_alive()
        assert not errors
        assert acquired.is_set()
        assert lock._waiters == []
        assert not lock._held
        lock.acquire(timeout=0.1)
        lock.release()

    def test_default_exceeds_sqlite_busy_timeout(self):
        assert DEFAULT_WRITE_LOCK_TIMEOUT > 30

    def test_acquire_times_out_and_leaves_lock_consistent(self, lock, caplog):
        lock.acquire()
        errors = []

        def waiter():
            try:
                lock.acquire(timeout=0.1)
            except WriteLockTimeout as exc:
                errors.append(exc)

        t = threading.Thread(target=waiter, name="timeout-waiter")
        with caplog.at_level(logging.WARNING, logger="src.extensions"):
            t.start()
            t.join(timeout=5)
        assert not t.is_alive()
        assert len(errors) == 1
        assert "SQLite write lock" in str(errors[0])
        assert "timeout-waiter" in caplog.text
        # The timed-out waiter is gone; the holder still owns the lock.
        assert lock._waiters == []
        assert lock._held

        lock.release()
        assert not lock._held
        lock.acquire(timeout=0.1)
        lock.release()

    def test_acquire_uses_environment_timeout(self, lock, monkeypatch):
        monkeypatch.setenv("VULNSCOUT_DB_WRITE_LOCK_TIMEOUT", "0.05")
        lock.acquire()
        start = time.monotonic()
        with pytest.raises(WriteLockTimeout):
            lock.acquire()
        assert time.monotonic() - start < 5
        assert lock._waiters == []

    def test_timeout_keeps_other_waiters(self, lock):
        lock.acquire()
        acquired = threading.Event()

        def patient():
            lock.acquire(timeout=5)
            acquired.set()
            lock.release()

        t = threading.Thread(target=patient)
        t.start()
        deadline = time.monotonic() + 5
        while len(lock._waiters) < 1 and time.monotonic() < deadline:
            time.sleep(0.01)
        with pytest.raises(WriteLockTimeout):
            lock.acquire(timeout=0.05)
        assert len(lock._waiters) == 1

        lock.release()
        assert acquired.wait(timeout=5)
        t.join(timeout=5)
        assert not lock._held and lock._waiters == []

    def test_handoff_racing_with_timeout_counts_as_acquired(self, lock, monkeypatch):
        """release() handing ownership over as the wait times out must not leak."""
        test_thread = threading.current_thread()
        real_event = threading.Event

        class RacyEvent(real_event):
            def wait(self, timeout=None):
                if threading.current_thread() is not test_thread:
                    return super().wait(timeout)
                lock.release()      # hands ownership to this waiter...
                return False        # ...just as the wait reports a timeout

        lock.acquire()
        monkeypatch.setattr(threading, "Event", RacyEvent)
        try:
            lock.acquire(timeout=0.01)
        finally:
            monkeypatch.setattr(threading, "Event", real_event)
        assert lock._held
        assert lock._waiters == []
        assert lock._owner == test_thread.name
        lock.release()
        assert not lock._held

    def test_callers_do_not_mark_lock_held_on_timeout(self, app, monkeypatch):
        """before_flush, hold_write_lock and write_lock leak nothing on timeout."""
        from src.models.project import Project
        monkeypatch.setenv("VULNSCOUT_DB_WRITE_LOCK_TIMEOUT", "0.05")
        _db_write_lock.acquire()    # held, but not by this thread's session

        with pytest.raises(WriteLockTimeout):
            with write_lock():
                pass                # pragma: no cover
        assert not getattr(_write_lock_state, "held", False)

        with pytest.raises(WriteLockTimeout):
            hold_write_lock()
        assert not getattr(_write_lock_state, "held", False)

        _db.session.add(Project(name="TimedOut"))
        with pytest.raises(WriteLockTimeout):
            _db.session.flush()
        assert not getattr(_write_lock_state, "held", False)
        assert _db_write_lock._waiters == []

        _db_write_lock.release()
        assert not _db_write_lock._held
        _db.session.flush()
        _db.session.commit()
        assert not _db_write_lock._held


# ===================================================================
# Leak regressions: transactions that end without commit/rollback events
# ===================================================================

@pytest.fixture()
def file_app(monkeypatch, tmp_path):
    """App on a file database, so requests and threads use real connections."""
    (tmp_path / "status").write_text("__END_OF_SCAN_SCRIPT__")
    monkeypatch.setenv("FLASK_SQLALCHEMY_DATABASE_URI", f"sqlite:///{tmp_path / 'lock.db'}")
    monkeypatch.setenv("FLASK_TESTING", "true")
    monkeypatch.setenv("FLASK_SCAN_FILE", str(tmp_path / "status"))
    monkeypatch.setenv("VULNSCOUT_DB_WRITE_LOCK_TIMEOUT", "5")
    from src.bin.webapp import create_app
    from src.models.project import Project
    application = create_app()
    application.config["PROPAGATE_EXCEPTIONS"] = False

    @application.post("/_test/flush-then-fail")
    def flush_then_fail():
        _db.session.add(Project(name="flush-then-fail"))
        _db.session.flush()
        raise ValueError("boom after flush")

    @application.post("/_test/commit")
    def commit_project():
        _db.session.add(Project(name=f"commit-{time.monotonic_ns()}"))
        _db.session.commit()
        return "ok"

    with application.app_context():
        _db.create_all()
    yield application
    with application.app_context():
        _db.session.remove()
        _db.engine.dispose()


def _write_from_thread(app, name):
    """Commit one row from a worker thread; return whether it finished in time."""
    from src.models.project import Project
    errors = []

    def writer():
        try:
            with app.app_context():
                _db.session.execute(_db.text("SELECT 1"))   # hold a connection first
                _db.session.add(Project(name=name))
                _db.session.commit()
        except Exception as exc:    # pragma: no cover - surfaced below
            errors.append(exc)

    t = threading.Thread(target=writer, name=f"writer-{name}")
    t.start()
    t.join(timeout=10)
    return not t.is_alive() and not errors


class TestWriteLockLeak:

    def test_request_failing_after_flush_releases_lock(self, file_app):
        client = file_app.test_client()
        assert client.post("/_test/flush-then-fail").status_code == 500
        assert not _db_write_lock._held

        assert _write_from_thread(file_app, "after-failed-request")
        assert client.post("/_test/commit").status_code == 200
        assert not _db_write_lock._held

    def test_failed_commit_releases_lock(self, file_app):
        def refuse_commit(_conn):
            raise OperationalError("COMMIT", {}, Exception("disk I/O error"))

        client = file_app.test_client()
        with file_app.app_context():
            engine = _db.engine
        event.listen(engine, "commit", refuse_commit)
        try:
            assert client.post("/_test/commit").status_code == 500
        finally:
            event.remove(engine, "commit", refuse_commit)
        assert not _db_write_lock._held

        assert _write_from_thread(file_app, "after-failed-commit")
        assert client.post("/_test/commit").status_code == 200
        assert not _db_write_lock._held

    def test_concurrent_writers_complete_after_failure(self, file_app):
        client = file_app.test_client()
        assert client.post("/_test/flush-then-fail").status_code == 500
        results = []
        threads = [
            threading.Thread(target=lambda i=i: results.append(_write_from_thread(file_app, f"w{i}")))
            for i in range(20)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        assert results == [True] * 20
        assert not _db_write_lock._held and _db_write_lock._waiters == []
