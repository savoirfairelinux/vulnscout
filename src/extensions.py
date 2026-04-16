from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy.orm import DeclarativeBase
from contextlib import contextmanager
import logging
import time

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


#: Shared SQLAlchemy instance.  Bind it to the app with ``db.init_app(app)``.
db = SQLAlchemy(model_class=Base)

migrate = Migrate()

#: Maximum number of times to retry a flush/commit that fails with
#: "database is locked" before giving up.
_MAX_RETRIES = 5
_RETRY_DELAY = 1.0  # seconds between retries


def _is_locked_error(exc: BaseException) -> bool:
    """Return True when *exc* (or its chain) wraps a SQLite
    ``database is locked`` error."""
    cur: BaseException | None = exc
    while cur is not None:
        if "database is locked" in str(cur):
            return True
        cur = cur.__cause__ or cur.__context__  # type: ignore[assignment]
    return False


@contextmanager
def batch_session():
    """Context manager that defers all ``db.session.commit()`` calls to a
    single commit at the end of the block.  Inside the block every
    ``commit()`` is silently replaced by ``flush()`` so that
    auto-generated PKs are available but no individual SQLite transaction
    is opened per row.

    When no Flask application context is active (e.g. during direct
    ``main()`` invocation in e2e tests) the body executes normally
    without batching.

    If a flush or the final commit fails with *database is locked*
    (SQLite contention with the background enrichment thread), the
    session is rolled back, all pending objects are re-added, and the
    operation is retried up to ``_MAX_RETRIES`` times.

    Usage::

        with batch_session():
            # hundreds of Package.create / Vulnerability.create_record / …
            ...
        # a single COMMIT happens here
    """
    try:
        session = db.session
        session.get_bind()
        original_commit = session.commit
    except (RuntimeError, Exception):
        yield None
        return

    def _deferred_commit():
        """Replace ``commit()`` with ``flush()`` inside the batch block.

        On *database is locked* we snapshot ``session.new`` / dirty
        objects, rollback (which evicts them), re-``add`` them, wait,
        and retry.
        """
        for attempt in range(_MAX_RETRIES):
            # Snapshot objects that would be lost on rollback.
            pending_new = list(session.new)
            pending_dirty = [
                (obj, {
                    attr.key: attr.history
                    for attr in db.inspect(obj).attrs
                    if attr.history.has_changes()
                })
                for obj in session.dirty
            ]
            try:
                session.flush()
                return
            except Exception as exc:
                if _is_locked_error(exc) \
                        and attempt < _MAX_RETRIES - 1:
                    logger.warning(
                        "database is locked during flush, "
                        "retrying (%d/%d)",
                        attempt + 1, _MAX_RETRIES,
                    )
                    session.rollback()
                    # Re-attach evicted objects.
                    for obj in pending_new:
                        session.add(obj)
                    for obj, _ in pending_dirty:
                        session.add(obj)
                    time.sleep(_RETRY_DELAY)
                    continue
                raise

    session.commit = _deferred_commit  # type: ignore[assignment]
    try:
        yield session
        # Final commit — same retry logic.
        for attempt in range(_MAX_RETRIES):
            pending_new = list(session.new)
            pending_dirty = list(session.dirty)
            try:
                original_commit()
                break
            except Exception as exc:
                if _is_locked_error(exc) \
                        and attempt < _MAX_RETRIES - 1:
                    logger.warning(
                        "database is locked during commit, "
                        "retrying (%d/%d)",
                        attempt + 1, _MAX_RETRIES,
                    )
                    session.rollback()
                    for obj in pending_new:
                        session.add(obj)
                    for obj in pending_dirty:
                        session.add(obj)
                    time.sleep(_RETRY_DELAY)
                    continue
                raise
    except Exception:
        try:
            session.rollback()
        except Exception:
            pass
        raise
    finally:
        session.commit = original_commit  # type: ignore[assignment]
