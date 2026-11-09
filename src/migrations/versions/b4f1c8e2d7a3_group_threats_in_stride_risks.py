# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Let a STRIDE risk group several threats: ``threat_id`` becomes ``R<n>`` + ``threat_ids``.

The rule is inlined (not imported from app code) so this revision stays frozen. The
agent-facing text is rendered on read, and its meaning is unchanged, so
``updated_at`` is left alone and existing assessments do not turn stale.
Downgrade is lossy: a risk keeps only its first threat, and ids/descriptions are dropped.
"""

import json

from alembic import op
import sqlalchemy as sa

revision = 'b4f1c8e2d7a3'
down_revision = 'e91a47b28c60'
branch_labels = None
depends_on = None

_KEPT_KEYS = ('likelihood', 'impact', 'mitigation', 'residual')


def _upgrade_risk(index, risk):
    if not isinstance(risk, dict) or 'threat_ids' in risk or 'threat_id' not in risk:
        return risk
    legacy = risk['threat_id']
    return {
        'id': f'R{index}', 'description': '',
        'threat_ids': [] if legacy in (None, '') else [legacy],
        **{key: risk.get(key) for key in _KEPT_KEYS},
    }


def _downgrade_risk(_index, risk):
    if not isinstance(risk, dict) or 'threat_ids' not in risk:
        return risk
    first = (risk['threat_ids'] or [''])[0]
    return {'threat_id': first, **{key: risk.get(key) for key in _KEPT_KEYS}}


def _rewrite(convert):
    connection = op.get_bind()
    rows = connection.execute(sa.text(
        "SELECT id, stride_model FROM variant_context WHERE stride_model IS NOT NULL")).all()
    update = sa.text("UPDATE variant_context SET stride_model = :model WHERE id = :id").bindparams(
        sa.bindparam('model', type_=sa.JSON))
    for row_id, raw in rows:
        model = json.loads(raw) if isinstance(raw, str) else raw
        if not isinstance(model, dict) or not isinstance(model.get('risks'), list):
            continue
        risks = [convert(index, risk) for index, risk in enumerate(model['risks'], start=1)]
        if risks != model['risks']:
            connection.execute(update, {'model': {**model, 'risks': risks}, 'id': row_id})


def upgrade():
    _rewrite(_upgrade_risk)


def downgrade():
    _rewrite(_downgrade_risk)
