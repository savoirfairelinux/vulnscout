# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Database resources shared by the backend test suite."""

import os
from pathlib import Path
import subprocess

import pytest
from sqlalchemy import event
from sqlalchemy.engine import Connection, Engine


@pytest.fixture(scope="module")
def postgres_uri(tmp_path_factory):
    configured_uri = os.getenv("VULNSCOUT_TEST_POSTGRES_URI")
    if configured_uri:
        yield configured_uri
        return

    bin_dir = Path(subprocess.run(
        ["pg_config", "--bindir"], check=True, capture_output=True, text=True,
    ).stdout.strip())
    directory = tmp_path_factory.mktemp("postgres")
    data_dir = directory / "data"
    socket_dir = directory / "socket"
    socket_dir.mkdir()
    subprocess.run(
        [str(bin_dir / "initdb"), "-D", str(data_dir), "-U", "vulnscout_test",
         "--auth=trust", "--no-locale", "-E", "UTF8"],
        check=True,
    )
    subprocess.run(
        [str(bin_dir / "pg_ctl"), "-D", str(data_dir), "-l", str(directory / "postgres.log"),
         "-o", f"-k {socket_dir} -c listen_addresses=''", "-w", "start"],
        check=True,
    )
    try:
        yield f"postgresql+psycopg2://vulnscout_test@/postgres?host={socket_dir}"
    finally:
        subprocess.run(
            [str(bin_dir / "pg_ctl"), "-D", str(data_dir), "-m", "fast", "-w", "stop"],
            check=True,
        )


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
