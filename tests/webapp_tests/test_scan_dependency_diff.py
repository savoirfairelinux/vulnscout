"""Import history compares frozen package-pair links, never mutable live edges."""

import json
from datetime import datetime, timezone
from importlib import import_module

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import inspect, text

from src.bin.cmd_process import read_inputs
from src.bin.webapp import create_app
from src.controllers import ControllersCache
from src.extensions import db
from src.models import PackageDependency, Project, SBOMDocument, Scan, Variant


@pytest.fixture()
def app(monkeypatch, tmp_path):
    monkeypatch.setenv('FLASK_SQLALCHEMY_DATABASE_URI', 'sqlite:///:memory:')
    application = create_app()
    status = tmp_path / 'scan-status'
    status.write_text('__END_OF_SCAN_SCRIPT__\n')
    application.config.update(TESTING=True, SCAN_FILE=str(status))
    with application.app_context():
        db.create_all()
        yield application
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def imports(app, tmp_path):
    variant = Variant.create('main', Project.create('dependency-history').id)

    def create(edges=(), *, owner=None, name='inventory.json', fmt='cdx', version='1'):
        scan = Scan.create('Import', owner or variant.id)
        path = tmp_path / f'{scan.id}.json'
        path.write_text(json.dumps({
            'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
            'components': [
                {'type': 'library', 'bom-ref': name, 'name': name,
                 'version': version if name == 'lib' else '1'}
                for name in ('app', 'lib', 'util')
            ],
            'dependencies': [{'ref': source, 'dependsOn': [target]} for source, target in edges],
        }))
        doc = SBOMDocument.create(str(path), name, scan.id, format=fmt)
        read_inputs(ControllersCache(), scan.id)
        return scan, doc

    return create


def diff(app, scan):
    response = app.test_client().get(f'/api/scans/{scan.id}/diff')
    assert response.status_code == 200
    return response.json


def unavailable(result, status):
    assert result['dependency_changes'] == {
        'status': status, 'added': None, 'removed': None, 'added_count': None, 'removed_count': None,
    }


def test_first_import_has_no_dependency_baseline(app, imports):
    scan, doc = imports([('app', 'lib')])
    assert doc.dependencies_recorded and len(doc.dependency_snapshot) == 1
    unavailable(diff(app, scan), 'no_previous_import')


@pytest.mark.parametrize('edges', [[], [('app', 'lib')]])
def test_identical_reimports_have_no_edge_or_package_changes(app, imports, edges):
    first, _ = imports(edges)
    second, _ = imports(edges)
    result = diff(app, second)
    assert result['previous_scan_id'] == str(first.id)
    assert result['dependency_changes'] == {
        'status': 'available', 'added_count': 0, 'removed_count': 0, 'added': [], 'removed': [],
    }
    assert not result['packages_added'] and not result['packages_removed'] and not result['packages_upgraded']


def test_edge_changes_separate_from_package_changes_and_preserve_direction(app, imports):
    imports([('app', 'lib')])
    scan, _ = imports([('lib', 'app'), ('app', 'util')])
    result = diff(app, scan)
    changes = result['dependency_changes']
    assert (changes['added_count'], changes['removed_count']) == (2, 1)
    assert [(e['dependent']['package_name'], e['dependency']['package_name']) for e in changes['added']] == [
        ('app', 'util'), ('lib', 'app'),
    ]
    assert changes['removed'][0]['dependency']['package_name'] == 'lib'
    assert not result['packages_added'] and not result['packages_removed'] and not result['packages_upgraded']


def test_recorded_empty_graph_is_real_removal(app, imports):
    imports([('app', 'lib')])
    scan, doc = imports()
    assert doc.dependency_snapshot == []
    assert diff(app, scan)['dependency_changes']['removed_count'] == 1


@pytest.mark.parametrize('side', ['current', 'previous'])
@pytest.mark.parametrize('missing', ['flag', 'snapshot'])
def test_missing_recording_on_either_side_never_looks_like_deletion(app, imports, side, missing):
    _, before = imports([('app', 'lib')])
    scan, current = imports()
    document = current if side == 'current' else before
    if missing == 'flag':
        document.dependencies_recorded = False
    else:
        document.dependency_snapshot = None
    db.session.commit()
    unavailable(diff(app, scan), 'not_recorded')


def test_does_not_skip_unrecorded_predecessor(app, imports):
    imports([('app', 'lib')])
    middle, doc = imports()
    doc.dependency_snapshot = None
    db.session.commit()
    scan, _ = imports([('app', 'util')])
    result = diff(app, scan)
    assert result['previous_scan_id'] == str(middle.id)
    unavailable(result, 'not_recorded')


@pytest.mark.parametrize('scope_change', ['filename', 'format', 'extra_document', 'duplicate_document'])
def test_incomparable_scope_never_reports_edge_changes(app, imports, scope_change):
    imports([('app', 'lib')])
    scan, doc = imports()
    if scope_change == 'filename':
        doc.source_name = 'other.json'
    elif scope_change == 'format':
        doc.format = 'spdx'
    else:
        SBOMDocument.create('missing', doc.source_name if scope_change == 'duplicate_document' else 'extra',
                            scan.id, format=doc.format)
    db.session.commit()
    unavailable(diff(app, scan), 'incomparable_scope')


def test_baseline_is_immediate_sbom_in_same_variant_with_uuid_tiebreaker(app, imports):
    first, _ = imports([('app', 'lib')])
    first.timestamp = datetime(2026, 1, 1, tzinfo=timezone.utc)
    tool = Scan.create('tool', first.variant_id, scan_type='tool', scan_source='nvd')
    other_variant = Variant.create('other', first.variant.project_id)
    imports([('app', 'util')], owner=other_variant.id)
    second, _ = imports()
    second.timestamp = first.timestamp
    # Equal timestamps follow the same UUID ordering as the existing history.
    earlier, later = sorted([first, second], key=lambda s: s.id)
    db.session.commit()
    result = diff(app, later)
    assert result['previous_scan_id'] == str(earlier.id)
    assert sum(result['dependency_changes'][key] for key in ('added_count', 'removed_count')) == 1
    unavailable(diff(app, tool), 'not_applicable')


def test_history_is_independent_of_live_edge_replacement_and_missing_files(app, imports):
    first, before = imports([('app', 'lib')])
    scan, current = imports([('app', 'util')])
    expected = diff(app, scan)['dependency_changes']
    PackageDependency.replace_for_documents({before.id, current.id}, set())
    from pathlib import Path
    Path(before.path).unlink()
    Path(current.path).unlink()
    read_inputs(ControllersCache(), first.id)
    read_inputs(ControllersCache(), scan.id)
    assert diff(app, scan)['dependency_changes'] == expected


def test_upgrade_links_compared_by_package_identity(app, imports):
    imports([('app', 'lib')])
    scan, _ = imports([('app', 'lib')], version='2')
    result = diff(app, scan)
    changes = result['dependency_changes']
    assert (changes['added_count'], changes['removed_count']) == (1, 1)
    assert changes['removed'][0]['dependency']['package_version'] == '1'
    assert changes['added'][0]['dependency']['package_version'] == '2'
    assert len(result['packages_upgraded']) == 1


def test_snapshot_migration_keeps_legacy_imports_unknown(app, imports):
    _, document = imports([('app', 'lib')])
    assert document.dependency_snapshot
    db.session.remove()
    migration = import_module('src.migrations.versions.b4e6f8a0c2d4_add_import_dependency_snapshots')
    with db.engine.begin() as connection:
        with Operations.context(MigrationContext.configure(connection)):
            migration.downgrade()
            assert 'dependency_snapshot' not in {c['name'] for c in inspect(connection).get_columns('sbom_documents')}
            migration.upgrade()
        assert connection.execute(text('SELECT dependency_snapshot FROM sbom_documents')).scalar() is None
        assert connection.execute(text('SELECT COUNT(*) FROM package_dependencies')).scalar() == 1


def test_unrecorded_import_cannot_be_rebuilt_from_live_edges(app, imports):
    scan, doc = imports([('app', 'lib')])
    doc.dependency_snapshot = None
    db.session.commit()
    from pathlib import Path
    Path(doc.path).unlink()
    read_inputs(ControllersCache(), scan.id)
    assert doc.dependency_snapshot is None


def test_other_variant_cannot_supply_a_first_import_baseline(app, imports):
    imports([('app', 'lib')])
    variant = Variant.create('isolated', Project.get_all()[0].id)
    scan, _ = imports(owner=variant.id)
    unavailable(diff(app, scan), 'no_previous_import')


def test_empty_document_inventory_is_not_a_comparable_graph(app):
    variant = Variant.create('empty', Project.create('empty').id)
    Scan.create('first', variant.id)
    scan = Scan.create('second', variant.id)
    unavailable(diff(app, scan), 'incomparable_scope')


def test_document_union_deduplicates_links_and_ignores_path_and_order(app, imports):
    first, first_doc = imports([('app', 'lib')])
    second, second_doc = imports([('app', 'lib')])
    for scan, document in [(second, second_doc), (first, first_doc)]:
        duplicate = SBOMDocument.create('another/upload/path', 'companion.json', scan.id, format='cdx')
        duplicate.dependencies_recorded = True
        duplicate.dependency_snapshot = document.dependency_snapshot
    db.session.commit()
    changes = diff(app, second)['dependency_changes']
    assert changes['status'] == 'available'
    assert changes['added_count'] == changes['removed_count'] == 0


def test_changed_scope_does_not_skip_to_older_matching_import(app, imports):
    imports([('app', 'lib')])
    previous, _ = imports(name='other.json')
    scan, _ = imports([('app', 'util')])
    result = diff(app, scan)
    assert result['previous_scan_id'] == str(previous.id)
    unavailable(result, 'incomparable_scope')


def test_parse_failure_does_not_record_an_empty_snapshot(app, imports, tmp_path):
    first, _ = imports([('app', 'lib')])
    scan = Scan.create('broken', first.variant_id)
    path = tmp_path / 'broken.json'
    path.write_text('{not JSON')
    document = SBOMDocument.create(str(path), 'inventory.json', scan.id, format='cdx')
    with pytest.raises(ValueError):
        read_inputs(ControllersCache(), scan.id)
    db.session.rollback()
    assert not document.dependencies_recorded
    assert document.dependency_snapshot is None
    unavailable(diff(app, scan), 'not_recorded')


@pytest.mark.parametrize('ignore_parsing_errors', ['false', 'true'])
def test_cross_document_snapshots_follow_final_resolution_and_ignore_relation_type(
        app, tmp_path, monkeypatch, ignore_parsing_errors):
    from tests.webapp_tests.test_package_dependencies import _yocto_archive

    monkeypatch.setenv('IGNORE_PARSING_ERRORS', ignore_parsing_errors)
    variant = Variant.create('cross-document', Project.create('cross-document').id)
    for iteration in range(2):
        scan = Scan.create('Import', variant.id)
        documents = _yocto_archive()
        if iteration:
            relation = documents['recipe-app']['relationships'][0]
            relation['relationshipType'] = 'RUNTIME_DEPENDENCY_OF'
        for name, document in reversed(list(documents.items())):
            path = tmp_path / f'{iteration}-{name}.json'
            path.write_text(json.dumps(document))
            SBOMDocument.create(str(path), name, scan.id, format='spdx')
        read_inputs(ControllersCache(), scan.id)
        stored = SBOMDocument.get_by_scan(scan.id)
        assert all(document.dependency_snapshot is not None for document in stored)
        assert sum(len(document.dependency_snapshot) for document in stored) == 2
    result = diff(app, scan)['dependency_changes']
    assert result['status'] == 'available'
    assert result['added_count'] == result['removed_count'] == 0


def test_dependency_scope_metadata_is_not_a_package_pair_change(app, tmp_path):
    from tests.webapp_tests.test_package_dependencies import _spdx3

    variant = Variant.create('scoped', Project.create('scoped').id)
    for iteration, scope in enumerate(('build', 'runtime')):
        scan = Scan.create('Import', variant.id)
        document = _spdx3()
        for item in document['@graph']:
            if item.get('type') == 'LifecycleScopedRelationship':
                item['scope'] = scope
        path = tmp_path / f'scoped-{iteration}.json'
        path.write_text(json.dumps(document))
        SBOMDocument.create(str(path), 'inventory.spdx.json', scan.id, format='spdx')
        read_inputs(ControllersCache(), scan.id)
    changes = diff(app, scan)['dependency_changes']
    assert changes['status'] == 'available'
    assert changes['added_count'] == changes['removed_count'] == 0
