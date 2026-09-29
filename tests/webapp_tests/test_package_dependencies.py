"""Ingest real SBOM relationships and read their document-scoped API graphs."""

import json
import os

import pytest
from sqlalchemy import inspect, text

from src.bin.webapp import create_app
from src.bin.cmd_process import read_inputs
from src.controllers import ControllersCache
from src.extensions import db
from src.models import PackageDependency, Project, SBOMDocument, SBOMPackage, Scan, Variant


@pytest.fixture()
def app(tmp_path):
    os.environ['FLASK_SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    try:
        application = create_app()
        status = tmp_path / 'scan-status'
        status.write_text('__END_OF_SCAN_SCRIPT__\n')
        application.config.update(TESTING=True, SCAN_FILE=str(status))
        with application.app_context():
            db.create_all()
            yield application
            db.session.remove()
            db.drop_all()
    finally:
        os.environ.pop('FLASK_SQLALCHEMY_DATABASE_URI', None)


def _scan(app, tmp_path, name, document, fmt='spdx'):
    with app.app_context():
        project = Project.get_all()[0] if Project.get_all() else Project.create('dep-project')
        variant = Variant.create(name, project.id)
        scan = Scan.create('SBOM', variant.id)
        path = tmp_path / f'{name}.json'
        path.write_text(json.dumps(document))
        SBOMDocument.create(str(path), path.name, scan.id, format=fmt)
        read_inputs(ControllersCache(), scan.id)
        return variant.id, scan.id


def _spdx3():
    return {'@graph': [
        {'type': 'CreationInfo', 'specVersion': '3.0.1'},
        *({'type': 'software_Package', 'spdxId': f'pkg:{name}',
            'name': name, 'software_packageVersion': '1.0'} for name in ('app', 'lib', 'util')),
        {'type': 'Relationship', 'relationshipType': 'dependsOn',
         'from': 'pkg:app', 'to': ['pkg:lib', 'pkg:util', 'pkg:missing']},
        {'type': 'Relationship', 'relationshipType': 'dependencyOf',
         'from': 'pkg:util', 'to': ['pkg:lib']},
        {'type': 'Relationship', 'relationshipType': 'describes',
         'from': 'pkg:app', 'to': ['pkg:util']},
    ]}


def test_spdx3_ingestion_and_scoped_api(app, tmp_path):
    variant, scan_id = _scan(app, tmp_path, 'one', _spdx3())
    client = app.test_client()
    response = client.get(f'/api/package-dependencies?variant_id={variant}')
    assert response.status_code == 200
    document = response.json['documents'][0]
    names = {package['id']: package['name'] for package in document['packages']}
    assert set(names) == {'app@1.0', 'lib@1.0', 'util@1.0'}
    assert set(names.values()) == {'app', 'lib', 'util'}
    assert {(names[edge['package_id']], names[edge['dependency_id']]) for edge in document['edges']} == {
        ('app', 'lib'), ('app', 'util'), ('lib', 'util'),
    }
    with app.app_context():
        read_inputs(ControllersCache(), scan_id)
        assert db.session.query(PackageDependency).count() == 3

    other, _ = _scan(app, tmp_path, 'two', {
        '@graph': [{'type': 'CreationInfo', 'specVersion': '3.0.1'},
                   {'type': 'software_Package', 'spdxId': 'pkg:a', 'name': 'app', 'software_packageVersion': '1.0'},
                   {'type': 'software_Package', 'spdxId': 'pkg:b', 'name': 'other', 'software_packageVersion': '1.0'},
                   {'type': 'Relationship', 'relationshipType': 'dependsOn', 'from': 'pkg:a', 'to': ['pkg:b']}],
    })
    assert len(client.get(f'/api/package-dependencies?variant_id={variant}').json['documents']) == 1
    assert len(client.get(f'/api/package-dependencies?variant_id={other}').json['documents']) == 1
    project_id = client.get(f'/api/package-dependencies?variant_ids={variant},{other}').json['documents']
    assert len(project_id) == 2
    assert len(client.get(f'/api/package-dependencies?project_id={Project.get_all()[0].id}').json['documents']) == 2
    assert client.get('/api/package-dependencies').status_code == 400
    assert client.get('/api/package-dependencies?variant_id=invalid').status_code == 400
    assert client.get('/api/package-dependencies?variant_ids=,').status_code == 400


def test_reingesting_document_replaces_removed_relationships(app, tmp_path):
    variant, scan_id = _scan(app, tmp_path, 'updated', _spdx3())
    replacement = _spdx3()
    replacement['@graph'] = [
        item for item in replacement['@graph']
        if item.get('relationshipType') != 'dependsOn'
    ]
    (tmp_path / 'updated.json').write_text(json.dumps(replacement))

    with app.app_context():
        read_inputs(ControllersCache(), scan_id)

    document = app.test_client().get(f'/api/package-dependencies?variant_id={variant}').json['documents'][0]
    names = {package['id']: package['name'] for package in document['packages']}
    assert {(names[edge['package_id']], names[edge['dependency_id']]) for edge in document['edges']} == {
        ('lib', 'util'),
    }


def test_deleting_scan_removes_dependency_edges(app, tmp_path):
    _, scan_id = _scan(app, tmp_path, 'removed', _spdx3())
    with app.app_context():
        assert db.session.query(PackageDependency).count() == 3
        Scan.get_by_id(scan_id).delete()
        assert db.session.query(PackageDependency).count() == 0


def test_deleting_package_link_removes_incoming_and_outgoing_edges(app, tmp_path):
    _, scan_id = _scan(app, tmp_path, 'link', _spdx3())
    with app.app_context():
        document_id = SBOMDocument.get_by_scan(scan_id)[0].id
        linked = SBOMPackage.get_by_document(document_id)
        app_link = next(link for link in linked if link.package.name == 'app')
        app_link.delete()
        assert db.session.query(PackageDependency).count() == 1
        util_link = next(link for link in linked if link.package.name == 'util')
        util_link.delete()
        assert db.session.query(PackageDependency).count() == 0


def test_outdated_cleanup_keeps_reactivated_graph_consistent(app, tmp_path):
    variant_id, older_scan_id = _scan(app, tmp_path, 'older', _spdx3())
    with app.app_context():
        newer_scan = Scan.create('SBOM', variant_id)
        document = {'@graph': [
            {'type': 'CreationInfo', 'specVersion': '3.0.1'},
            {'type': 'software_Package', 'spdxId': 'pkg:app',
             'name': 'app', 'software_packageVersion': '1.0'},
        ]}
        path = tmp_path / 'newer.json'
        path.write_text(json.dumps(document))
        SBOMDocument.create(str(path), path.name, newer_scan.id, format='spdx')
        read_inputs(ControllersCache(), newer_scan.id)

        from src.helpers.outdated_cleanup import delete_outdated_data
        assert delete_outdated_data()['sbom_packages_deleted'] == 2
        assert db.session.query(PackageDependency).count() == 0
        newer_scan.delete()

    graph = app.test_client().get(f'/api/package-dependencies?variant_id={variant_id}')
    assert graph.status_code == 200
    assert graph.json['documents'][0]['edges'] == []
    with app.app_context():
        assert Scan.get_by_id(older_scan_id) is not None


def test_comparison_graph_matches_package_selection(app, tmp_path):
    base_id, _ = _scan(app, tmp_path, 'base', _spdx3())
    compare_id, _ = _scan(app, tmp_path, 'compare', {'@graph': [
        {'type': 'CreationInfo', 'specVersion': '3.0.1'},
        *({'type': 'software_Package', 'spdxId': f'pkg:{name}',
            'name': name, 'software_packageVersion': '1.0'}
          for name in ('app', 'core', 'other')),
        {'type': 'Relationship', 'relationshipType': 'dependsOn',
         'from': 'pkg:app', 'to': ['pkg:core']},
        {'type': 'Relationship', 'relationshipType': 'dependsOn',
         'from': 'pkg:core', 'to': ['pkg:other']},
    ]})
    client = app.test_client()
    for operation, expected_names, expected_edges in (
        ('difference', {'core', 'other'}, 1),
        ('intersection', {'app'}, 0),
    ):
        query = f'variant_id={base_id}&compare_variant_id={compare_id}&operation={operation}'
        packages = client.get(f'/api/packages?{query}').json
        graph = client.get(f'/api/package-dependencies?{query}')
        assert graph.status_code == 200
        documents = graph.json['documents']
        assert len(documents) == (1 if operation == 'difference' else 2)
        assert {package['name'] for doc in documents for package in doc['packages']} == expected_names
        assert {package['name'] for package in packages} == expected_names
        assert sum(len(doc['edges']) for doc in documents) == expected_edges

    intersection = client.get(
        f'/api/package-dependencies?variant_ids={base_id},{compare_id}&operation=intersection'
    )
    assert intersection.status_code == 200
    assert {package['name'] for doc in intersection.json['documents']
            for package in doc['packages']} == {'app'}


@pytest.mark.parametrize('format_name,document', [
    ('spdx', {
        'spdxVersion': 'SPDX-2.3', 'SPDXID': 'SPDXRef-DOCUMENT',
        'creationInfo': {'creators': ['Tool: test'], 'created': '2024-01-01T00:00:00Z'},
        'name': 'test', 'dataLicense': 'CC0-1.0', 'documentNamespace': 'https://example.org/deps',
        'packages': [{'SPDXID': f'SPDXRef-{name}', 'name': name, 'versionInfo': '1.0',
                      'downloadLocation': 'NOASSERTION'} for name in ('app', 'lib')],
        'relationships': [{'spdxElementId': 'SPDXRef-app', 'relationshipType': 'DEPENDS_ON',
                           'relatedSpdxElement': 'SPDXRef-lib'}],
    }),
    ('cdx', {
        'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'version': 1,
        'components': [{'type': 'library', 'bom-ref': name, 'name': name, 'version': '1.0'}
                       for name in ('app', 'lib')],
        'dependencies': [{'ref': 'app', 'dependsOn': ['lib']}],
    }),
])
def test_supported_formats_ingest_dependencies(app, tmp_path, format_name, document):
    variant, _ = _scan(app, tmp_path, format_name, document, format_name)
    graph = app.test_client().get(f'/api/package-dependencies?variant_id={variant}').json['documents'][0]
    assert len(graph['packages']) == 2
    assert len(graph['edges']) == 1


def test_migration_creates_composite_membership_constraints(app):
    from importlib import import_module
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    migration = import_module('src.migrations.versions.z2c3d4e5f6a7_add_package_dependencies')
    with app.app_context(), db.engine.begin() as connection:
        PackageDependency.__table__.drop(connection)
        context = MigrationContext.configure(connection)
        with Operations.context(context):
            migration.upgrade()
            keys = inspect(connection).get_foreign_keys('package_dependencies')
            assert sum(key['referred_table'] == 'sbom_packages' for key in keys) == 2
            migration.downgrade()
        assert 'package_dependencies' not in inspect(connection).get_table_names()