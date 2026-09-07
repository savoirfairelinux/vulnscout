# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Guards against a migration graph that alembic cannot walk.

Two branches adding a migration in parallel can easily pick the same
revision id or the same ``down_revision``; either mistake only surfaces at
``alembic upgrade`` time, in production.

The version files are read with ``ast`` rather than imported: importing them
would drag every migration module into the coverage report, and their bodies
only run during an actual upgrade.
"""

import ast
import os

VERSIONS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    'src', 'migrations', 'versions',
)


def _module_level_strings(path: str) -> dict:
    """Return the module-level ``name = 'value'`` assignments of a version file."""
    tree = ast.parse(open(path, encoding='utf-8').read(), filename=path)
    found = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and isinstance(node.value, ast.Constant):
                found[target.id] = node.value.value
    return found


def _revisions() -> list:
    files = sorted(f for f in os.listdir(VERSIONS_DIR) if f.endswith('.py'))
    return [(name, _module_level_strings(os.path.join(VERSIONS_DIR, name))) for name in files]


def test_every_migration_declares_a_revision():
    for name, fields in _revisions():
        assert fields.get('revision'), f'{name} declares no revision id'


def test_revision_ids_are_unique():
    ids = [fields['revision'] for _, fields in _revisions()]

    duplicates = {rev for rev in ids if ids.count(rev) > 1}

    assert not duplicates, f'several migrations share revision id(s) {sorted(duplicates)}'


def test_no_two_migrations_share_a_parent():
    parents = [fields.get('down_revision') for _, fields in _revisions()]
    parents = [parent for parent in parents if parent]

    duplicates = {parent for parent in parents if parents.count(parent) > 1}

    assert not duplicates, f'the graph forks after revision(s) {sorted(duplicates)}'


def test_the_graph_has_exactly_one_head():
    revisions = _revisions()
    ids = {fields['revision'] for _, fields in revisions}
    parents = {fields.get('down_revision') for _, fields in revisions}

    heads = ids - parents

    assert len(heads) == 1, f'alembic cannot pick an upgrade path between heads {sorted(heads)}'
