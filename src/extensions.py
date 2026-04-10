from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy.orm import DeclarativeBase
from contextlib import contextmanager


class Base(DeclarativeBase):
    pass


#: Shared SQLAlchemy instance.  Bind it to the app with ``db.init_app(app)``.
db = SQLAlchemy(model_class=Base)

migrate = Migrate()


@contextmanager
def batch_session():
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
        # Force the scoped-session proxy to resolve — this will raise
        # RuntimeError when there is no Flask app context.
        session = db.session
        session.get_bind()
        original_commit = session.commit
    except (RuntimeError, Exception):
        # No Flask app context or no DB binding — run the block without batching
        yield None
        return

    def _deferred_commit():
        session.flush()

    session.commit = _deferred_commit  # type: ignore[assignment]
    try:
        yield session
        original_commit()  # single real commit
    except Exception:
        try:
            session.rollback()
        except Exception:
            pass
        raise
    finally:
        session.commit = original_commit  # type: ignore[assignment]
