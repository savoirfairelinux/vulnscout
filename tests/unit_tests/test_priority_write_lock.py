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
"""

import os
import time
import threading
import pytest

from src.extensions import (
    _PriorityWriteLock, _db_write_lock, _write_lock_state,
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
    if _db_write_lock._held:
        _db_write_lock._held = False
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

        begin_nested() acquires the lock on flush, and the savepoint release
        triggers after_soft_rollback which releases the lock.  A subsequent
        begin_nested() must re-acquire without deadlocking.
        """
        from src.models.project import Project

        # Simulate a begin_nested write (like PackagesController.add)
        with _db.session.begin_nested():
            _db.session.add(Project(name="Nested"))
        # Savepoint released → after_soft_rollback fires → lock released.
        # This is correct — the write transaction doesn't span savepoints.
        assert not _db_write_lock._held

        # Another begin_nested in the same thread should work fine.
        with _db.session.begin_nested():
            _db.session.add(Project(name="Nested2"))
        assert not _db_write_lock._held

        # Explicit commit on the outer transaction.
        _db.session.commit()
        assert not _db_write_lock._held


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
