# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Database resource cleanup shared by the backend test suite."""

import pytest
from sqlalchemy import event
from sqlalchemy.engine import Connection, Engine


@pytest.fixture(scope="module", autouse=True)
def dispose_database_engines():
    """Close test connection pools after the module's database fixtures finish."""
    engines: set[Engine] = set()

    def track_engine(connection: Connection) -> None:
        engines.add(connection.engine)

    # Module scope preserves databases shared by module-scoped fixtures.
    event.listen(Engine, "engine_connect", track_engine)
    try:
        yield
    finally:
        event.remove(Engine, "engine_connect", track_engine)
        for engine in engines:
            engine.dispose()
