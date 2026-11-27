from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy.orm import DeclarativeBase, Session, SessionTransaction
from sqlalchemy import event
from contextlib import contextmanager
from typing import Generator
import logging
import math
import os
import threading

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


#: Shared SQLAlchemy instance.  Bind it to the app with ``db.init_app(app)``.
db = SQLAlchemy(model_class=Base)

migrate = Migrate()

# ---------------------------------------------------------------------------
# SQLite write serialisation — priority lock
# ---------------------------------------------------------------------------
# SQLite only supports one writer at a time, even with WAL journal mode.
# When multiple threads (EPSS enrichment, NVD enrichment, Flask requests)
# try to write concurrently, "database is locked" errors occur because the
# busy_timeout expires while another thread holds a write transaction.
#
# The lock below serialises all write *transactions*.  It is acquired
# transparently on the first ``Session.flush()`` that contains pending
# writes and released when the outermost session transaction ends
# (``commit()``, ``rollback()`` or ``close()``).  Savepoints
# (``begin_nested()``) do not release it: SQLite keeps the write lock until
# the outer transaction ends.  Read-only sessions never touch the lock.
#
# Priority order (highest first):
#   0 — Flask request handlers             (interactive, latency-sensitive)
#   1 — EPSS enrichment thread             (fast API, small payloads)
#   2 — NVD enrichment thread              (slow API, can take minutes)
#
# When the lock is released and several threads are waiting, the one with
# the highest priority (lowest number) is woken first.
# ---------------------------------------------------------------------------


# Default bound on how long a writer waits for the lock.  It exceeds SQLite's
# 30 s busy_timeout so a holder stalled on SQLite itself can still finish, and
# leaves room for large batch writes, while ensuring that a lock that is never
# released fails writers loudly instead of pinning pooled connections forever.
DEFAULT_WRITE_LOCK_TIMEOUT = 300.0


def _bounded_write_lock_timeout(value: float) -> float:
    if not math.isfinite(value) or value > threading.TIMEOUT_MAX:
        logger.warning(
            "Invalid VULNSCOUT_DB_WRITE_LOCK_TIMEOUT=%r, using %ss",
            value, DEFAULT_WRITE_LOCK_TIMEOUT,
        )
        return DEFAULT_WRITE_LOCK_TIMEOUT
    return value


def write_lock_timeout() -> float | None:
    """Seconds to wait for the write lock (``VULNSCOUT_DB_WRITE_LOCK_TIMEOUT``).

    Non-positive values disable the timeout; invalid values use the default.
    """
    raw = os.getenv("VULNSCOUT_DB_WRITE_LOCK_TIMEOUT", "").strip()
    if not raw:
        return DEFAULT_WRITE_LOCK_TIMEOUT
    try:
        value = float(raw)
    except ValueError:
        logger.warning("Invalid VULNSCOUT_DB_WRITE_LOCK_TIMEOUT=%r, using %ss",
                       raw, DEFAULT_WRITE_LOCK_TIMEOUT)
        return DEFAULT_WRITE_LOCK_TIMEOUT
    value = _bounded_write_lock_timeout(value)
    return value if value > 0 else None


class WriteLockTimeout(RuntimeError):
    """Raised when the SQLite write lock cannot be acquired in time."""


class _PriorityWriteLock:
    """Write lock that wakes the highest-priority waiter first.

    Priority is auto-detected from ``threading.current_thread().name``.
    The interface (``acquire`` / ``release``) mirrors ``threading.Lock``
    so it can be used as a drop-in replacement.
    """

    _FLASK = 0
    _EPSS = 1
    _NVD = 2

    def __init__(self) -> None:
        self._mutex = threading.Lock()
        self._held = False
        self._owner: str | None = None  # thread name, for diagnostics only
        self._waiters: list = []  # [(priority, Event, thread name)]

    # ---- priority detection ------------------------------------------------

    @staticmethod
    def _thread_priority() -> int:
        name = threading.current_thread().name
        if "enrichment-nvd" in name:
            return _PriorityWriteLock._NVD
        if "enrichment-epss" in name:
            return _PriorityWriteLock._EPSS
        return _PriorityWriteLock._FLASK

    # ---- public API --------------------------------------------------------

    def acquire(self, timeout: float | None = None) -> None:
        """Block until the lock is owned by the calling thread.

        *timeout* defaults to :func:`write_lock_timeout`.  Raises
        :class:`WriteLockTimeout` when it expires; the lock is then not held
        by the caller.
        """
        if timeout is None:
            timeout = write_lock_timeout()
        else:
            timeout = _bounded_write_lock_timeout(timeout)
        priority = self._thread_priority()
        name = threading.current_thread().name
        evt = threading.Event()
        with self._mutex:
            if not self._held:
                self._held = True
                self._owner = name
                return
            self._waiters.append((priority, evt, name))
            self._waiters.sort(key=lambda w: w[0])
        # Block until release() hands ownership to us.
        if evt.wait(timeout):
            return
        with self._mutex:
            # release() may have handed ownership over just as the wait timed out.
            if evt.is_set():
                return
            self._waiters = [w for w in self._waiters if w[1] is not evt]
            owner = self._owner
        logger.warning(
            "Thread %r timed out after %ss waiting for the SQLite write lock (held by %r)",
            name, timeout, owner,
        )
        raise WriteLockTimeout(
            f"Could not acquire the SQLite write lock within {timeout}s (held by thread {owner!r})"
        )

    def release(self) -> None:
        with self._mutex:
            if not self._held:
                return
            if self._waiters:
                _prio, evt, name = self._waiters.pop(0)
                # _held stays True — ownership transfers to the woken thread
                self._owner = name
                evt.set()
            else:
                self._held = False
                self._owner = None


_db_write_lock = _PriorityWriteLock()

# Per-thread flag that tracks whether the *current thread* holds the write
# lock.  Using ``threading.local`` instead of a session attribute avoids the
# stale-session problem: in tests each ``create_app()`` yields a fresh
# Session, but the old Session's ``_holds_write_lock`` is lost while the
# module-level ``_db_write_lock._held`` stays True → deadlock on the next
# acquire in the same (single-threaded) test run.
_write_lock_state = threading.local()

# Guard so that listeners are registered exactly once, no matter how many
# times ``create_app()`` is called (each test fixture calls it).
_write_serialization_initialized = False


def setup_write_serialization(session_factory: object) -> None:
    """Register SQLAlchemy session events that serialise SQLite writes.

    Call once after ``db.init_app(app)`` when the engine is SQLite.  The
    events are registered on *session_factory* (typically ``db.session``,
    a ``scoped_session``).  Subsequent calls are no-ops.
    """
    global _write_serialization_initialized
    if _write_serialization_initialized:
        return
    _write_serialization_initialized = True

    def _release_lock(*_args: object, **_kwargs: object) -> None:
        if getattr(_write_lock_state, "held", False):
            _write_lock_state.held = False
            _db_write_lock.release()

    @event.listens_for(session_factory, "before_flush")
    def _before_flush(session: Session, flush_context: object, instances: object) -> None:  # type: ignore[assignment]
        # Only acquire if there are actual pending writes.
        if not (session.new or session.dirty or session.deleted):
            return
        if not getattr(_write_lock_state, "held", False):
            _db_write_lock.acquire()
            _write_lock_state.held = True

    def _root_transaction_over(session: Session) -> bool:
        # A savepoint commit/rollback leaves the root transaction active, and
        # SQLite keeps its write lock until that root transaction ends.
        root = session.get_transaction()
        return root is None or not root.is_active

    @event.listens_for(session_factory, "after_commit")
    def _after_commit(session: Session) -> None:  # type: ignore[assignment]
        if _root_transaction_over(session):
            _release_lock()

    @event.listens_for(session_factory, "after_soft_rollback")
    def _after_soft_rollback(session: Session, previous_transaction: object) -> None:  # type: ignore[assignment]
        if _root_transaction_over(session):
            _release_lock()

    @event.listens_for(session_factory, "after_transaction_end")
    def _after_transaction_end(session: Session, transaction: SessionTransaction) -> None:  # type: ignore[assignment]
        # Safety net for transactions that end without commit()/rollback()
        # events, e.g. close() after an unhandled error or a failed COMMIT.
        if transaction.parent is None:
            _release_lock()


def hold_write_lock() -> None:
    """Hold the write lock until the current session transaction ends.

    For Core INSERT/UPDATE statements executed through the session, which
    bypass the ``before_flush`` listener.  Unlike :func:`write_lock`, the lock
    is not released when the caller returns but by the session listeners when
    the outermost transaction ends, together with the SQLite transaction.
    """
    if not _write_serialization_initialized or getattr(_write_lock_state, "held", False):
        return
    _db_write_lock.acquire()
    _write_lock_state.held = True


@contextmanager
def write_lock() -> Generator[None, None, None]:
    """Hold the priority write lock for a block of manual/bulk writes.

    The ``before_flush`` listener only serialises unit-of-work flushes; bulk
    operations (``bulk_insert_mappings`` / ``executemany``) bypass it and would
    otherwise collide with concurrent SQLite writers (enrichment threads,
    request handlers).  Wrapping a bulk-insert-then-commit block in this context
    manager serialises it the same way a normal flush would.

    No-op when write serialisation is inactive (non-SQLite engines) or when the
    current thread already holds the lock (reentrant).  The session listeners
    release the lock when the outermost transaction ends; the ``finally`` here
    is an idempotent safety net.
    """
    if not _write_serialization_initialized or getattr(_write_lock_state, "held", False):
        yield
        return
    _db_write_lock.acquire()
    _write_lock_state.held = True
    try:
        yield
    finally:
        if getattr(_write_lock_state, "held", False):
            _write_lock_state.held = False
            _db_write_lock.release()


@contextmanager
def batch_session() -> Generator[object, None, None]:
    """Context manager that defers all ``db.session.commit()`` calls to a single
    commit at the end of the block.  Inside the block every ``commit()`` is
    silently replaced by ``flush()`` so that auto-generated PKs are available
    but no individual SQLite transaction is opened per row.

    When no Flask application context is active (e.g. during direct ``main()``
    invocation in e2e tests) the body executes normally without batching.

    Usage::

        with batch_session():
            # hundreds of Package.create / Vulnerability.create_record / …
            ...
        # a single COMMIT happens here
    """
    try:
        # Override only this context's session, not the shared session proxy.
        session = db.session()
        session.get_bind()
        original_commit = session.commit
    except (RuntimeError, Exception):
        # No Flask app context or no DB binding — run the block without batching
        yield None
        return

    def _deferred_commit() -> None:
        session.flush()

    session.commit = _deferred_commit  # type: ignore[assignment]
    try:
        yield session  # type: ignore[misc]
        original_commit()  # single real commit
    except Exception:
        try:
            session.rollback()
        except Exception:
            pass
        raise
    finally:
        session.commit = original_commit  # type: ignore[assignment]
