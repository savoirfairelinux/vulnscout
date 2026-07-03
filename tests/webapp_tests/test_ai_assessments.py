# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import json
import os
import uuid

import pytest

from src.bin.webapp import create_app
from src.extensions import db
from src.models.variant import Variant
from . import write_demo_files, setup_demo_db

VARIANT_UUID = uuid.UUID("22222222-2222-2222-2222-222222222222")
PROJECT_UUID = uuid.UUID("11111111-1111-1111-1111-111111111111")
VULN_ID = "CVE-2020-35492"
PKG = "cairo@1.16.0"
PKG2 = "abc@1.2.3"


@pytest.fixture()
def init_files(tmp_path):
    files = {
        "status": tmp_path / "status.txt",
        "packages": tmp_path / "packages-merged.json",
        "vulnerabilities": tmp_path / "vulnerabilities-merged.json",
        "assessments": tmp_path / "assessments-merged.json",
        "openvex": tmp_path / "openvex.json",
        "time_estimates": tmp_path / "time_estimates.json",
    }
    write_demo_files(files)
    return files


@pytest.fixture()
def app(init_files):
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        application = create_app()
        application.config.update({
            "TESTING": True,
            "SCAN_FILE": init_files["status"],
            "OPENVEX_FILE": init_files["openvex"],
            "NVD_DB_PATH": "webapp_tests/mini_nvd.db",
        })
        setup_demo_db(application)
        yield application
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture()
def client(app):
    return app.test_client()


def _post_ai(client, vuln_id=VULN_ID, packages=None, status="affected",
             variant_id=str(VARIANT_UUID), **extra):
    payload = {
        "packages": packages or [PKG],
        "status": status,
        "variant_id": variant_id,
        "ai_generated": True,
    }
    payload.update(extra)
    return client.post(f"/api/vulnerabilities/{vuln_id}/assessments", json=payload)


def test_ai_post_creates_ai_origin(client):
    resp = _post_ai(client)
    assert resp.status_code == 200
    body = json.loads(resp.data)
    assert body["assessments"]
    assert all(a["origin"] == "ai" for a in body["assessments"])


def test_ai_post_duplicate_rejected(client):
    first = _post_ai(client)
    assert first.status_code == 200

    second = _post_ai(client)
    assert second.status_code == 409
    body = json.loads(second.data)
    assert body["error"] == "A pending AI assessment already exists for this variant"


def test_ai_post_second_variant_allowed(client, app):
    first = _post_ai(client)
    assert first.status_code == 200

    other_variant = "22222222-2222-2222-2222-222222222223"
    with app.app_context():
        db.session.add(
            Variant(
                id=uuid.UUID(other_variant),
                project_id=PROJECT_UUID,
                name="variant-b",
            )
        )
        db.session.commit()

    second = _post_ai(client, variant_id=other_variant)
    assert second.status_code == 200


def test_non_ai_post_not_blocked_by_pending_ai(client):
    first = _post_ai(client)
    assert first.status_code == 200

    resp = client.post(
        f"/api/vulnerabilities/{VULN_ID}/assessments",
        json={
            "packages": [PKG],
            "status": "affected",
            "variant_id": str(VARIANT_UUID),
        },
    )
    assert resp.status_code == 200
