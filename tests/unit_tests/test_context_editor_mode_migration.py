# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Editor preferences migrate without changing stored context or timestamps."""

from sqlalchemy import inspect, text

from src.bin.webapp import create_app
from src.extensions import db


def test_editor_mode_upgrade_and_downgrade_preserve_existing_context(monkeypatch):
    monkeypatch.setenv("FLASK_SQLALCHEMY_DATABASE_URI", "sqlite:///:memory:")
    monkeypatch.setenv("SCAN_FILE", "/dev/null")
    monkeypatch.setattr("logging.config.fileConfig", lambda _filename: None)
    app = create_app()
    app.config["TESTING"] = True
    with app.app_context():
        runner = app.test_cli_runner()
        result = runner.invoke(args=["db", "upgrade", "c83e91ab402d"])
        assert result.exit_code == 0, result.output
        with db.engine.begin() as connection:
            connection.execute(text(
                "INSERT INTO projects (id, name) VALUES ('11111111111111111111111111111111', 'legacy')"
            ))
            connection.execute(text(
                "INSERT INTO variants (id, name, project_id) VALUES "
                "('22222222222222222222222222222222', 'default', '11111111111111111111111111111111')"
            ))
            connection.execute(text(
                "INSERT INTO variant_context (id, variant_id, threat_model, risks, updated_at) VALUES "
                "('33333333333333333333333333333333', '22222222222222222222222222222222', "
                "'  Legacy model  ', 'Legacy risks', '2026-01-01 00:00:00')"
            ))
        before = db.session.execute(text("SELECT threat_model, risks, updated_at FROM variant_context")).one()
        result = runner.invoke(args=["db", "upgrade"])
        assert result.exit_code == 0, result.output
        assert db.session.execute(text("SELECT editor_mode FROM variant_context")).scalar() is None
        assert db.session.execute(text("SELECT threat_model, risks, updated_at FROM variant_context")).one() == before
        result = runner.invoke(args=["db", "downgrade", "c83e91ab402d"])
        assert result.exit_code == 0, result.output
        assert "editor_mode" not in {column["name"] for column in inspect(db.engine).get_columns("variant_context")}
        assert db.session.execute(text("SELECT threat_model, risks, updated_at FROM variant_context")).one() == before
        db.session.remove()
        db.drop_all()
        db.engine.dispose()
