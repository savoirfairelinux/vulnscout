"""Ingest real SBOM relationships and read their document-scoped API graphs."""

import json
import os
from pathlib import Path

import pytest
from sqlalchemy import event, inspect, text

from src.bin.webapp import create_app
from src.bin.cmd_process import read_inputs
from src.controllers import ControllersCache
from src.extensions import db
from src.models import Finding, Package, PackageDependency, Project, SBOMDocument, SBOMPackage, Scan, Variant


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


def _package_in_scan(scan_id, string_id):
    document_ids = {doc.id for doc in SBOMDocument.get_by_scan(scan_id)}
    package = Package.get_by_string_id(string_id)
    evidence = SBOMPackage.evidence_for_documents(document_ids)
    return package.with_sbom_evidence(**evidence.get(package.id, {}))


def _spdx3():
    return {'@graph': [
        {'type': 'CreationInfo', 'specVersion': '3.0.1'},
        *({'type': 'software_Package', 'spdxId': f'pkg:{name}',
            'name': name, 'software_packageVersion': '1.0'} for name in ('app', 'lib', 'util')),
        {'type': 'LifecycleScopedRelationship', 'scope': 'build', 'relationshipType': 'dependsOn',
         'from': 'pkg:app', 'to': ['pkg:lib', 'pkg:util', 'pkg:missing']},
        {'type': 'Relationship', 'relationshipType': 'dependencyOf',
         'from': 'pkg:util', 'to': ['pkg:lib']},
        {'type': 'Relationship', 'relationshipType': 'describes',
         'from': 'pkg:app', 'to': ['pkg:util']},
    ]}


@pytest.mark.parametrize('queued', [False, True])
def test_dependency_replacement_ignores_raced_existence_check_and_preserves_other_documents(app, queued):
    from src.extensions import batch_session

    project = Project.create('replace-dependencies')
    variant = Variant.create('default', project.id)
    scan = Scan.create('SBOM', variant.id)
    document = SBOMDocument.create('one.json', 'one', scan.id)
    other_document = SBOMDocument.create('two.json', 'two', scan.id)
    ctrl = ControllersCache().packages
    ctrl.current_sbom_document = document
    source = ctrl.add(Package('app', '1'))
    dependency = ctrl.add(Package('lib', '1'))
    package_id, dependency_id = source.id, dependency.id
    document_id, other_document_id = document.id, other_document.id
    SBOMPackage.create(other_document.id, source.id)
    db.session.add(PackageDependency(
        sbom_document_id=other_document.id, package_id=source.id, dependency_id=dependency.id,
    ))
    db.session.commit()
    refs = {'pkg:app': source.string_id, 'pkg:lib': dependency.string_id}
    raced = False

    def insert_raced_edge(connection, cursor, statement, parameters, context, executemany):
        nonlocal raced
        if not raced and 'package_dependencies' in statement and statement.startswith(('DELETE', 'INSERT')):
            raced = True
            cursor.execute(
                'INSERT INTO package_dependencies (sbom_document_id, package_id, dependency_id) VALUES (?, ?, ?)',
                (document_id.hex, package_id.hex, dependency_id.hex),
            )

    engine = db.engine
    event.listen(engine, 'before_cursor_execute', insert_raced_edge)
    try:
        with batch_session():
            if queued:
                ctrl.add_spdx3_dependencies(refs, {}, {('pkg:app', 'pkg:lib')})
                ctrl.flush_spdx_dependencies()
            else:
                ctrl.add_dependencies(refs, {('pkg:app', 'pkg:lib')})
    finally:
        event.remove(engine, 'before_cursor_execute', insert_raced_edge)
    assert raced
    assert set(db.session.execute(db.select(
        PackageDependency.sbom_document_id, PackageDependency.package_id, PackageDependency.dependency_id,
    ))) == {(document_id, package_id, dependency_id), (other_document_id, package_id, dependency_id)}
    ctrl.add_dependencies(refs, set())
    assert [row.sbom_document_id for row in db.session.query(PackageDependency).all()] == [other_document_id]
    PackageDependency.replace_for_documents(set(), set())
    assert db.session.query(PackageDependency).count() == 1


def _zephyr_spdx3(elements, namespace='https://example.org/zephyr/', prefix='zephyr'):
    return {'@context': 'https://spdx.org/rdf/3.0.1/spdx-context.jsonld', '@graph': [
        {'type': 'CreationInfo', 'specVersion': '3.0.1'},
        {'type': 'SoftwareAgent', 'name': 'West SPDX Generator'},
        {'type': 'SpdxDocument', 'namespaceMap': [
            {'type': 'NamespaceMap', 'prefix': prefix, 'namespace': namespace},
        ]},
        *elements,
    ]}


def _grouping_documents(revision='a' * 40):
    prefix = 'https://example.org/zephyr/'
    def ref(name):
        return prefix + name

    def relation(kind, source, *targets):
        return {'type': 'Relationship', 'relationshipType': kind,
                'from': ref(source), 'to': [ref(target) for target in targets]}
    return {
        'build': _zephyr_spdx3([
            {'type': 'software_Package', 'spdxId': ref('mbedtls'), 'name': 'mbedtls'},
            {'type': 'build_Build', 'spdxId': ref('build')},
            relation('contains', 'mbedtls', 'library'),
            relation('hasOutput', 'build', 'library'),
            relation('hasInput', 'build', 'file'),
        ]),
        'sources': _zephyr_spdx3([
            {'type': 'software_Package', 'spdxId': ref('source'), 'name': 'mbedtls-sources',
             'software_primaryPurpose': 'source', 'software_packageVersion': revision},
            relation('contains', 'source', 'file'),
            relation('hasVariant', 'upstream', 'source'),
        ]),
        'upstream': _zephyr_spdx3([
            {'type': 'software_Package', 'spdxId': ref('upstream'), 'name': 'mbedtls-deps',
             'software_packageVersion': revision, 'externalIdentifier': [
                 {'externalIdentifierType': 'packageUrl', 'identifier': 'pkg:github/Mbed-TLS/mbedtls@v4.1.1'},
                 {'externalIdentifierType': 'cpe23',
                  'identifier': 'cpe:2.3:a:trustedfirmware:mbed_tls:4.1.1:*:*:*:*:*:*:*'},
             ]},
        ]),
    }


def _import_grouping_documents(tmp_path, variant, documents):
    scan = Scan.create('JSON-LD', variant.id)
    directory = tmp_path / str(scan.id)
    directory.mkdir()
    for name, document in documents.items():
        path = directory / f'{name}.jsonld'
        path.write_text(json.dumps(document))
        SBOMDocument.create(str(path), path.name, scan.id, format='spdx')
    read_inputs(ControllersCache(), scan.id)
    return scan


def _import_legacy_components(tmp_path, variant, documents, monkeypatch):
    with monkeypatch.context() as patch:
        patch.setattr('src.helpers.jsonld_storage.consolidate_jsonld_packages', lambda session: False)
        return _import_grouping_documents(tmp_path, variant, documents)


def test_canonical_package_keeps_an_unknown_release_separate_from_its_revision(app, tmp_path):
    documents = _grouping_documents()
    documents['upstream']['@graph'][-1]['externalIdentifier'] = []
    project = Project.create('unknown-release')
    variant = Variant.create('demo', project.id)
    _import_grouping_documents(tmp_path, variant, documents)
    assert len(Package.get_all()) == 1
    parent = Package.get_by_string_id('mbedtls@')
    assert parent.source_revisions == ['a' * 40]
    row = app.test_client().get(f'/api/packages?variant_id={variant.id}').json[0]
    assert row['release_version'] is None
    assert row['source_revision'] == 'a' * 40
    assert row['id'] == 'mbedtls@'


@pytest.mark.parametrize('ownership', ['unique', 'shared', 'multiple-targets'])
def test_generated_build_target_requires_unique_exclusive_source_ownership(app, tmp_path, ownership):
    documents = _grouping_documents()
    target_name = '..__modules__lib__mbedtls__zephyr'
    for node in documents['build']['@graph']:
        if node.get('name') == 'mbedtls':
            node['name'] = target_name
    prefix = 'https://example.org/zephyr/'
    if ownership == 'shared':
        documents['sources']['@graph'].extend([
            {'type': 'software_Package', 'spdxId': prefix + 'other-source',
             'name': 'other-sources', 'software_primaryPurpose': 'source'},
            {'type': 'Relationship', 'relationshipType': 'contains',
             'from': prefix + 'other-source', 'to': [prefix + 'file']},
        ])
    elif ownership == 'multiple-targets':
        documents['build']['@graph'].extend([
            {'type': 'software_Package', 'spdxId': prefix + 'other-target', 'name': 'other-target'},
            {'type': 'Relationship', 'relationshipType': 'contains',
             'from': prefix + 'other-target', 'to': [prefix + 'other-library']},
            {'type': 'Relationship', 'relationshipType': 'hasOutput',
             'from': prefix + 'build', 'to': [prefix + 'other-library']},
        ])
    project = Project.create('generated-build-target')
    variant = Variant.create('demo', project.id)
    _import_grouping_documents(tmp_path, variant, documents)
    rows = app.test_client().get(f'/api/packages?variant_id={variant.id}').json
    by_name = {row['name']: row for row in rows}
    parent = by_name['mbedtls']
    assert parent['id'] == 'mbedtls@4.1.1'
    if ownership == 'unique':
        assert len(Package.get_all()) == len(rows) == 1
        assert parent['component_types'] == ['built']
        assert target_name not in by_name
    else:
        assert len(Package.get_all()) == len(rows) == 3
        assert parent['component_types'] == ['workspace']
        assert by_name[target_name]['component_types'] == ['normal']


@pytest.mark.parametrize('owns_source', [False, True])
def test_module_target_with_zephyr_glue_requires_its_own_upstream_source(app, tmp_path, owns_source):
    documents = _grouping_documents()
    target_name = 'modules__mbedtls'
    prefix = 'https://example.org/zephyr/'
    for node in documents['build']['@graph']:
        if node.get('name') == 'mbedtls':
            node['name'] = target_name
    if not owns_source:
        documents['sources']['@graph'] = [
            node for node in documents['sources']['@graph']
            if node.get('relationshipType') != 'contains'
        ]
    documents['sources']['@graph'].extend([
        {'type': 'software_Package', 'spdxId': prefix + 'zephyr-source',
         'name': 'zephyr-sources', 'software_primaryPurpose': 'source'},
        {'type': 'Relationship', 'relationshipType': 'contains',
         'from': prefix + 'zephyr-source', 'to': [prefix + 'wrapper-file']},
    ])
    documents['build']['@graph'].append({
        'type': 'Relationship', 'relationshipType': 'hasInput',
        'from': prefix + 'build', 'to': [prefix + 'wrapper-file'],
    })
    project = Project.create('module-with-zephyr-glue')
    variant = Variant.create('demo', project.id)
    _import_grouping_documents(tmp_path, variant, documents)
    rows = app.test_client().get(f'/api/packages?variant_id={variant.id}').json
    by_name = {row['name']: row for row in rows}
    parent = by_name['mbedtls']
    assert parent['id'] == 'mbedtls@4.1.1'
    assert by_name['zephyr-sources']['component_types'] == ['normal']
    if owns_source:
        assert len(Package.get_all()) == len(rows) == 2
        assert parent['component_types'] == ['built']
        assert target_name not in by_name
    else:
        assert len(Package.get_all()) == len(rows) == 3
        assert parent['component_types'] == ['workspace']
        assert by_name[target_name]['component_types'] == ['normal']


@pytest.mark.parametrize('target_name', ['mbedtls', 'modules__mbedtls'])
def test_ambiguous_named_targets_preserve_the_workspace_pair(app, tmp_path, target_name):
    documents = _grouping_documents()
    prefix = 'https://example.org/zephyr/'
    documents['build']['@graph'][3]['name'] = target_name
    documents['build']['@graph'].extend([
        {'type': 'software_Package', 'spdxId': prefix + 'other-target',
         'name': target_name, 'software_packageVersion': 'other'},
        {'type': 'Relationship', 'relationshipType': 'contains',
         'from': prefix + 'other-target', 'to': [prefix + 'library']},
    ])
    project = Project.create('ambiguous-named-targets')
    variant = Variant.create('demo', project.id)
    scan = _import_grouping_documents(tmp_path, variant, documents)
    rows = app.test_client().get(f'/api/packages?variant_id={variant.id}').json
    assert len(rows) == len(Package.get_all()) == 3
    parent = next(row for row in rows if row['id'] == 'mbedtls@4.1.1')
    assert parent['component_types'] == ['workspace']
    assert parent['source_revision'] == 'a' * 40
    assert {row['id'] for row in rows if row is not parent} == {
        f'{target_name}@', f'{target_name}@other',
    }
    assert all(row['component_types'] == ['normal'] for row in rows if row is not parent)
    groups = [group for document in SBOMDocument.get_by_scan(scan.id) for group in document.jsonld_groups or []]
    assert len(groups) == 1
    assert not groups[0]['built']
    assert {member['role'] for member in groups[0]['members']} == {'source', 'upstream'}


@pytest.mark.parametrize('built_first', [False, True])
def test_same_release_groups_union_scoped_evidence_and_retain_revision_conflicts(
        app, tmp_path, monkeypatch, built_first):
    from unittest.mock import Mock
    from src.helpers.export_scope import compute_export_scope

    project = Project.create('multiple-checkouts')
    variant = Variant.create('demo', project.id)
    documents = {}
    purls = ['pkg:github/mbed-tls/mbedtls@v4.1.1', 'pkg:generic/mbedtls@4.1.1?arch=arm64']
    cpes = [f'cpe:2.3:a:{vendor}:mbed_tls:4.1.1:*:*:*:*:*:*:*' for vendor in ('trustedfirmware', 'example')]
    urls = [f'git+https://example.org/mbedtls@{revision * 40}' for revision in ('a', 'b')]
    for index, revision in enumerate(('a' * 40, 'b' * 40)):
        group = _grouping_documents(revision)
        if bool(index) == built_first:
            group.pop('build')
        upstream = group['upstream']['@graph'][-1]
        upstream['externalIdentifier'][0]['identifier'] = purls[index]
        upstream['externalIdentifier'][1]['identifier'] = cpes[index]
        upstream['software_downloadLocation'] = urls[index]
        group = json.loads(json.dumps(group).replace(
            'https://example.org/zephyr/', f'https://example.org/checkout-{index}/',
        ))
        documents.update({f'{index}-{name}': data for name, data in group.items()})
    scan = _import_grouping_documents(tmp_path, variant, documents)
    assert len(Package.get_all()) == 1
    parent = Package.get_by_string_id('mbedtls@4.1.1')
    for link in db.session.query(SBOMPackage):
        assert link.package_id == parent.id
        assert set(link.source_revisions) == {'a' * 40, 'b' * 40}
        assert set(link.purl) >= set(purls)
        assert set(link.cpe) >= set(cpes)
        assert set(link.source_urls) == set(urls)
        assert link.type == 'built'
    client = app.test_client()
    row = client.get(f'/api/packages?variant_id={variant.id}').json[0]
    assert row['revision_conflict']
    assert set(row['source_revisions']) == {'a' * 40, 'b' * 40}
    assert set(row['purl']) >= set(purls)
    graphs = client.get(f'/api/package-dependencies?variant_id={variant.id}').json['documents']
    assert len(graphs) == len(SBOMDocument.get_by_scan(scan.id))
    assert all(document['packages'][0]['revision_conflict'] for document in graphs)
    controllers = ControllersCache(scope=compute_export_scope(variant_id=variant.id))
    controllers.packages._preload_cache()
    exported = list(controllers.packages)
    assert len(exported) == 1
    assert exported[0].version_info['revision_conflict']
    assert set(exported[0].source_revisions) == {'a' * 40, 'b' * 40}
    assert set(exported[0].purl) >= set(purls)
    osv = Mock()
    osv.query_by_purl.return_value = []
    monkeypatch.setattr('src.bin.cmd_vuln_scan.OSVClient', lambda: osv)
    result = app.test_cli_runner().invoke(args=[
        'osv-scan', '--project', project.name, '--variant', variant.name,
    ])
    assert result.exit_code == 0, result.output
    assert {call.args[0] for call in osv.query_by_purl.call_args_list} >= set(purls)


def test_consolidation_loads_only_pending_links_and_member_history(app, tmp_path, monkeypatch):
    from unittest.mock import Mock
    from src.helpers import jsonld_storage

    project = Project.create('bounded-consolidation')
    variant = Variant.create('incoming', project.id)
    documents = {}
    for index in range(10):
        group = json.loads(json.dumps(_grouping_documents()).replace(
            'https://example.org/zephyr/', f'https://example.org/group-{index}/',
        ).replace('mbedtls', f'lib{index}'))
        documents.update({f'{index}-{name}': data for name, data in group.items()})
    scan = _import_legacy_components(tmp_path, variant, documents, monkeypatch)
    member_ids = {link.package_id for document in SBOMDocument.get_by_scan(scan.id)
                  for link in SBOMPackage.get_by_document(document.id)}
    history = Variant.create('history', project.id)
    old_scan = Scan.create('Historical SBOM', history.id)
    old_document = SBOMDocument.create('historical.json', 'historical', old_scan.id)
    source = Package.get_by_string_id('lib0-sources@' + 'a' * 40)
    source_id, old_document_id = source.id, old_document.id
    SBOMPackage.create(old_document_id, source_id)
    for index in range(50):
        package = Package.find_or_create(f'unrelated-{index}', '1')
        db.session.add(SBOMPackage(sbom_document_id=old_document_id, package_id=package.id))
    db.session.commit()
    db.session.remove()
    loaded = set()

    def record_loaded(link, context):
        loaded.add((link.sbom_document_id, link.package_id))

    original_metadata = jsonld_storage._metadata

    def metadata_for_members(group, packages, links):
        assert {str(link.package_id) for link in links} == {member['package_id'] for member in group['members']}
        assert len(links) == 3
        return original_metadata(group, packages, links)

    metadata = Mock(side_effect=metadata_for_members)
    monkeypatch.setattr(jsonld_storage, '_metadata', metadata)
    event.listen(SBOMPackage, 'load', record_loaded)
    try:
        assert jsonld_storage.consolidate_jsonld_packages(db.session())
        db.session.commit()
    finally:
        event.remove(SBOMPackage, 'load', record_loaded)
    assert {package_id for _, package_id in loaded} <= member_ids
    assert (old_document_id, source_id) in loaded
    assert metadata.call_count == 10
    assert SBOMPackage.get(old_document_id, source_id) is not None
    assert len(SBOMPackage.get_by_document(old_document_id)) == 51


def test_package_types_are_scoped_without_duplicating_the_parent(app, tmp_path):
    project = Project.create('scoped-component-types')
    built = Variant.create('built', project.id)
    built_scan = _import_grouping_documents(tmp_path, built, _grouping_documents())
    workspace = Variant.create('workspace', project.id)
    documents = _grouping_documents()
    documents.pop('build')
    workspace_scan = _import_grouping_documents(tmp_path, workspace, documents)
    ordinary = Variant.create('ordinary', project.id)
    ordinary_scan = Scan.create('Ordinary SBOM', ordinary.id)
    ordinary_document = SBOMDocument.create('ordinary.json', 'ordinary', ordinary_scan.id, format='cdx')
    parent = Package.get_by_string_id('mbedtls@4.1.1')
    parent_id = parent.id
    link = SBOMPackage.create(ordinary_document.id, parent.id)
    assert link.type == 'normal'
    client = app.test_client()
    for variant, expected in ((built, 'built'), (workspace, 'workspace'), (ordinary, 'normal')):
        rows = client.get(f'/api/packages?variant_id={variant.id}').json
        assert len(rows) == 1
        assert rows[0]['package_id'] == str(parent_id)
        assert rows[0]['component_types'] == [expected]
    rows = client.get(f'/api/packages?project_id={project.id}').json
    assert len(rows) == len(Package.get_all()) == 1
    assert rows[0]['component_types'] == ['built', 'normal', 'workspace']
    for scan, expected in ((built_scan, 'built'), (workspace_scan, 'workspace'), (ordinary_scan, 'normal')):
        links = db.session.query(SBOMPackage).join(SBOMDocument).filter(SBOMDocument.scan_id == scan.id).all()
        assert {link.type for link in links} == {expected}
    assert 'type' not in {column['name'] for column in inspect(db.engine).get_columns('packages')}


def test_type_migration_backfills_canonical_groups_without_input_files_or_new_packages(app, tmp_path):
    from importlib import import_module
    from alembic import op
    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    from sqlalchemy.exc import IntegrityError

    project = Project.create('component-type-migration')
    built = Variant.create('built', project.id)
    built_scan = _import_grouping_documents(tmp_path, built, _grouping_documents())
    workspace = Variant.create('workspace', project.id)
    documents = _grouping_documents()
    documents.pop('build')
    workspace_scan = _import_grouping_documents(tmp_path, workspace, documents)
    parent = Package.get_by_string_id('mbedtls@4.1.1')
    ordinary_document = SBOMDocument.create('ordinary.json', 'ordinary', built_scan.id, format='cdx')
    SBOMPackage.create(ordinary_document.id, parent.id)
    expected = {document.id: 'built' for document in SBOMDocument.get_by_scan(built_scan.id)
                if document.id != ordinary_document.id}
    expected.update({document.id: 'workspace' for document in SBOMDocument.get_by_scan(workspace_scan.id)})
    expected[ordinary_document.id] = 'normal'
    parent_id = parent.id
    for document in SBOMDocument.get_all():
        path = Path(document.path)
        if path.exists():
            path.unlink()
    db.session.remove()
    migration = import_module('src.migrations.versions.d8f63a29b104_add_scoped_package_types')
    with db.engine.begin() as connection:
        with Operations.context(MigrationContext.configure(connection)):
            # Preserve existing grouping provenance while exercising type backfill.
            with op.batch_alter_table('sbom_packages') as batch_op:
                batch_op.drop_constraint('ck_sbom_packages_type', type_='check')
                batch_op.drop_column('type')
            assert 'type' not in {column['name'] for column in inspect(connection).get_columns('sbom_packages')}
            migration.upgrade()
        assert connection.execute(text('SELECT count(*) FROM packages')).scalar() == 1
        with pytest.raises(IntegrityError):
            with connection.begin_nested():
                connection.execute(text("UPDATE sbom_packages SET type = 'unexpected'"))
    assert Package.get_by_string_id('mbedtls@4.1.1').id == parent_id
    assert {link.sbom_document_id: link.type for link in db.session.query(SBOMPackage)} == expected
    assert all(link.package_id == parent_id for link in db.session.query(SBOMPackage))


def test_jsonld_storage_migration_preserves_findings_assessments_and_evidence(app, tmp_path, monkeypatch):
    from importlib import import_module
    from alembic import op
    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    from src.models import Assessment, Observation, SBOMObservation, Vulnerability
    from src.models.assessment_review import AssessmentReview
    from src.models.assessment_target import AssessmentTarget
    from src.models.time_estimate import TimeEstimate

    project = Project.create('legacy-component-storage')
    variant = Variant.create('demo', project.id)
    scan = _import_legacy_components(tmp_path, variant, _grouping_documents(), monkeypatch)
    assert len(Package.get_all()) == 3
    parent = Package.get_by_string_id('mbedtls@')
    parent_id, variant_id = parent.id, variant.id
    vulnerability = Vulnerability.create_record(id='CVE-2026-1234')
    findings = [Finding.get_or_create(package.id, vulnerability.id) for package in Package.get_all()]
    for finding in findings:
        Observation.create(finding_id=finding.id, scan_id=scan.id)
    assessment = Assessment.create(
        source='custom', origin='custom', status='affected', simplified_status='Exploitable',
        status_notes='Original analyst judgment',
        targets=[(variant.id, finding.id) for finding in findings],
    )
    assessment_id = assessment.id
    for finding in findings:
        TimeEstimate.create(finding_id=finding.id, variant_id=variant.id, optimistic=1, likely=2, pessimistic=3)
    db.session.add(AssessmentReview(
        assessment_id=assessment.id, variant_id=variant.id, finding_id=findings[1].id,
        status='affected', rationale='Original review rationale', reviewed_fingerprint='original-fingerprint',
    ))
    source = Package.get_by_string_id('mbedtls-sources@' + 'a' * 40)
    source_document = SBOMPackage.get_by_package(source.id)[0].sbom_document_id
    observation = SBOMObservation.create(
        vulnerability.id, source_document, 'original-evidence', 'Original SBOM evidence', package_id=source.id,
    )
    observation_id = observation.id
    crypto = Package.find_or_create('crypto', '1')
    SBOMPackage.create(source_document, crypto.id)
    db.session.add_all([
        PackageDependency(sbom_document_id=source_document, package_id=source.id, dependency_id=parent.id),
        PackageDependency(sbom_document_id=source_document, package_id=source.id, dependency_id=crypto.id),
    ])
    db.session.commit()
    db.session.remove()
    migration = import_module('src.migrations.versions.d8f63a29b104_add_scoped_package_types')
    with db.engine.begin() as connection:
        with Operations.context(MigrationContext.configure(connection)):
            # Keep recorded groups to exercise consolidation of legacy package rows.
            with op.batch_alter_table('sbom_packages') as batch_op:
                batch_op.drop_constraint('ck_sbom_packages_type', type_='check')
                batch_op.drop_column('type')
                batch_op.drop_column('source_revisions')
            with op.batch_alter_table('packages') as batch_op:
                batch_op.drop_column('source_revisions')
            assert 'source_revisions' not in {column['name'] for column in inspect(connection).get_columns('packages')}
            migration.upgrade()
        assert connection.execute(text('SELECT count(*) FROM packages')).scalar() == 2
    parent = Package.get_by_string_id('mbedtls@4.1.1')
    assert parent.id == parent_id
    assert parent.source_revisions == ['a' * 40]
    assert {link.type for link in SBOMPackage.get_by_package(parent.id)} == {'built'}
    assert len(Finding.get_all()) == 1
    finding = Finding.get_all()[0]
    assert finding.package_id == parent.id
    assert db.session.query(Observation).count() == 1
    assert db.session.query(Assessment).count() == 1
    assessment = db.session.get(Assessment, assessment_id)
    assert assessment.status_notes == 'Original analyst judgment'
    assert assessment.packages == ['mbedtls@4.1.1']
    assert assessment.targets == [(variant_id, finding.id)]
    assert db.session.query(AssessmentTarget).count() == 1
    assert db.session.query(TimeEstimate).count() == 1
    estimate = db.session.query(TimeEstimate).one()
    assert (estimate.finding_id, estimate.optimistic, estimate.likely, estimate.pessimistic) == (finding.id, 1, 2, 3)
    review = db.session.query(AssessmentReview).one()
    assert review.finding_id == finding.id
    assert review.rationale == 'Original review rationale'
    assert review.reviewed_fingerprint == 'original-fingerprint'
    observation = db.session.get(SBOMObservation, observation_id)
    assert observation.package_id == parent.id
    assert observation.description == 'Original SBOM evidence'
    edges = db.session.query(PackageDependency).all()
    assert len(edges) == 1
    assert edges[0].package_id == parent.id
    assert edges[0].dependency_id == Package.get_by_string_id('crypto@1').id
    response = app.test_client().post('/api/vulnerabilities/CVE-2026-1234/assessments', json={
        'status': 'not_affected', 'justification': 'vulnerable_code_not_present',
        'status_notes': 'Assessment of the actual parent', 'packages': ['mbedtls@4.1.1'],
        'variant_id': str(variant_id),
    })
    assert response.status_code == 200, response.json
    assert response.json['assessment']['packages'] == ['mbedtls@4.1.1']
    assert {target.finding.package_id for target in db.session.query(AssessmentTarget).all()} == {parent_id}


def test_consolidation_keeps_unrelated_non_zephyr_findings_and_targets(app, tmp_path, monkeypatch):
    from src.helpers.jsonld_storage import consolidate_jsonld_packages
    from src.models import Assessment, Observation, Vulnerability
    from src.models.assessment_target import AssessmentTarget

    project = Project.create('mixed-storage')
    variant = Variant.create('west', project.id)
    scan = _import_legacy_components(tmp_path, variant, _grouping_documents(), monkeypatch)
    other = Variant.create('yocto', project.id)
    other_scan = Scan.create('Unrelated SBOM', other.id)
    other_document = SBOMDocument.create('yocto.json', 'yocto', other_scan.id, format='yocto_cve_check')
    source = Package.get_by_string_id('mbedtls-sources@' + 'a' * 40)
    source_id = source.id
    SBOMPackage.create(other_document.id, source.id)
    vulnerability = Vulnerability.create_record(id='CVE-2026-1235')
    finding = Finding.get_or_create(source.id, vulnerability.id)
    for context in (scan, other_scan):
        Observation.create(finding_id=finding.id, scan_id=context.id)
    assessment = Assessment.create(
        source='custom', origin='custom', status='affected', simplified_status='Exploitable',
        targets=[(context.id, finding.id) for context in (variant, other)],
    )
    assessment_id = assessment.id
    db.session.execute(text('PRAGMA foreign_keys=ON'))
    assert db.session.execute(text('PRAGMA foreign_keys')).scalar() == 1
    assert consolidate_jsonld_packages(db.session())
    db.session.commit()
    parent = Package.get_by_string_id('mbedtls@4.1.1')
    assert Package.get_by_string_id('mbedtls-sources@' + 'a' * 40).id == source_id
    pairs = {(target.variant_id, target.finding.package_id)
             for target in db.session.query(AssessmentTarget).filter_by(assessment_id=assessment_id)}
    assert pairs == {(variant.id, parent.id), (other.id, source_id)}
    observations = {(observation.scan_id, observation.finding.package_id)
                    for observation in db.session.query(Observation)}
    assert observations == {(scan.id, parent.id), (other_scan.id, source_id)}
    assert db.session.execute(text('PRAGMA foreign_key_check')).all() == []


def test_legacy_unversioned_build_references_follow_each_release_scan(app, tmp_path, monkeypatch):
    from src.helpers.jsonld_storage import consolidate_jsonld_packages
    from src.models import Assessment, Observation, Vulnerability
    from src.models.assessment_target import AssessmentTarget

    project = Project.create('legacy-releases')
    variant = Variant.create('demo', project.id)
    first = _import_legacy_components(tmp_path, variant, _grouping_documents(), monkeypatch)
    upgraded = json.loads(json.dumps(_grouping_documents('b' * 40)).replace('4.1.1', '4.2.0'))
    second = _import_legacy_components(tmp_path, variant, upgraded, monkeypatch)
    vulnerability = Vulnerability.create_record(id='CVE-2026-1236')
    finding = Finding.get_or_create(Package.get_by_string_id('mbedtls@').id, vulnerability.id)
    for scan in (first, second):
        Observation.create(finding_id=finding.id, scan_id=scan.id)
    assessment = Assessment.create(
        source='custom', origin='custom', status='affected', simplified_status='Exploitable',
        targets=[(variant.id, finding.id)],
    )
    assessment_id = assessment.id
    assert consolidate_jsonld_packages(db.session())
    db.session.commit()
    assert len(Package.get_all()) == 2
    assert Package.get_by_string_id('mbedtls@') is None
    observations = {(observation.scan_id, observation.finding.package.string_id)
                    for observation in db.session.query(Observation)}
    assert observations == {(first.id, 'mbedtls@4.1.1'), (second.id, 'mbedtls@4.2.0')}
    assert {target.finding.package.string_id for target in
            db.session.query(AssessmentTarget).filter_by(assessment_id=assessment_id)} == {
                'mbedtls@4.1.1', 'mbedtls@4.2.0',
            }


def test_tool_observations_use_cached_variant_sbom_predecessors(app, tmp_path, monkeypatch):
    from bisect import bisect_right
    from datetime import datetime, timedelta, timezone
    from unittest.mock import Mock
    from uuid import UUID, uuid4

    from src.helpers.jsonld_storage import consolidate_jsonld_packages
    from src.models import Observation, Vulnerability

    project = Project.create('tool-predecessors')
    variant = Variant.create('demo', project.id)
    first = _import_legacy_components(tmp_path, variant, _grouping_documents(), monkeypatch)
    upgraded = json.loads(json.dumps(_grouping_documents('b' * 40)).replace('4.1.1', '4.2.0'))
    second = _import_legacy_components(tmp_path, variant, upgraded, monkeypatch)
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    first.timestamp = base + timedelta(seconds=10)
    first.scan_type = None
    second.timestamp = base + timedelta(seconds=30)
    other = Variant.create('unrelated', project.id)
    unrelated = Scan.create('Unrelated SBOM', other.id)
    unrelated.timestamp = base + timedelta(seconds=25)
    cases = [
        ('before', 0, uuid4(), {'4.1.1', '4.2.0'}),
        ('between', 20, uuid4(), {'4.1.1'}),
        ('after', 40, uuid4(), {'4.2.0'}),
        ('tie-before', 10, UUID(int=0), {'4.1.1', '4.2.0'}),
        ('tie-after', 10, UUID(int=(1 << 128) - 1), {'4.1.1'}),
    ]
    expected = {}
    for name, seconds, scan_id, versions in cases:
        db.session.add(Scan(
            id=scan_id, description=name, variant_id=variant.id, scan_type='tool', scan_source='osv',
            timestamp=base + timedelta(seconds=seconds),
        ))
        expected[scan_id] = versions
    db.session.commit()
    for vuln_id in ('CVE-2026-1240', 'CVE-2026-1241'):
        vulnerability = Vulnerability.create_record(id=vuln_id)
        finding = Finding.get_or_create(Package.get_by_string_id('mbedtls@').id, vulnerability.id)
        for scan_id in expected:
            Observation.create(finding_id=finding.id, scan_id=scan_id)
    lookup = Mock(wraps=bisect_right)
    monkeypatch.setattr('src.helpers.jsonld_storage.bisect_right', lookup)
    assert consolidate_jsonld_packages(db.session())
    db.session.commit()
    assert lookup.call_count == len(expected)
    observations = {(observation.scan_id, observation.finding.vulnerability_id, observation.finding.package.version)
                    for observation in db.session.query(Observation)}
    assert observations == {
        (scan_id, vuln_id, version)
        for scan_id, versions in expected.items()
        for vuln_id in ('CVE-2026-1240', 'CVE-2026-1241')
        for version in versions
    }


def test_unambiguous_existing_finding_keeps_its_uuid_when_moved_to_parent(app, tmp_path, monkeypatch):
    from src.helpers.jsonld_storage import consolidate_jsonld_packages
    from src.models import Observation, Vulnerability

    project = Project.create('stable-finding')
    variant = Variant.create('demo', project.id)
    scan = _import_legacy_components(tmp_path, variant, _grouping_documents(), monkeypatch)
    vulnerability = Vulnerability.create_record(id='CVE-2026-1238')
    source = Package.get_by_string_id('mbedtls-sources@' + 'a' * 40)
    finding = Finding.get_or_create(source.id, vulnerability.id)
    observation = Observation.create(finding_id=finding.id, scan_id=scan.id)
    finding_id, observation_id = finding.id, observation.id
    assert consolidate_jsonld_packages(db.session())
    db.session.commit()
    assert len(Finding.get_all()) == 1
    assert Finding.get_all()[0].id == finding_id
    assert Finding.get_all()[0].package_id == Package.get_by_string_id('mbedtls@4.1.1').id
    assert db.session.get(Observation, observation_id).finding_id == finding_id


def test_ingestion_refreshes_cached_vulnerabilities_and_assessments_to_the_parent(app, tmp_path, monkeypatch):
    from src.models import Assessment, Vulnerability

    project = Project.create('canonical-import-caches')
    variant = Variant.create('demo', project.id)
    scan = _import_legacy_components(tmp_path, variant, _grouping_documents(), monkeypatch)
    source = Package.get_by_string_id('mbedtls-sources@' + 'a' * 40)
    original_id = source.string_id
    vulnerability = Vulnerability.create_record(id='CVE-2026-1239')
    Finding.get_or_create(source.id, vulnerability.id)
    controllers = ControllersCache()
    assert controllers.vulnerabilities.get(vulnerability.id).packages == [original_id]
    controllers.assessments.current_variant_id = variant.id
    assessment = Assessment.new_dto(vulnerability.id, [original_id])
    controllers.assessments.add(assessment)
    db.session.commit()
    read_inputs(controllers, scan.id)
    assert controllers.vulnerabilities.get(vulnerability.id).packages == ['mbedtls@4.1.1']
    assert controllers.assessments.get_by_id(assessment.id).packages == ['mbedtls@4.1.1']
    assert (vulnerability.id, original_id) not in controllers.assessments._by_vuln_pkg
    assert (vulnerability.id, 'mbedtls@4.1.1') in controllers.assessments._by_vuln_pkg
    assert len(list(controllers.packages)) == 1


@pytest.mark.parametrize('conflict', ['review', 'estimate'])
def test_conflicting_legacy_analyst_records_abort_without_data_loss(app, tmp_path, monkeypatch, conflict):
    from src.helpers.jsonld_storage import consolidate_jsonld_packages
    from src.models import Assessment, Vulnerability
    from src.models.assessment_review import AssessmentReview
    from src.models.time_estimate import TimeEstimate

    project = Project.create('legacy-conflicts')
    variant = Variant.create('demo', project.id)
    _import_legacy_components(tmp_path, variant, _grouping_documents(), monkeypatch)
    vulnerability = Vulnerability.create_record(id='CVE-2026-1237')
    findings = [Finding.get_or_create(package.id, vulnerability.id) for package in Package.get_all()]
    assessment = Assessment.create(
        source='custom', origin='custom', status='affected', simplified_status='Exploitable',
        targets=[(variant.id, finding.id) for finding in findings],
    )
    for index, finding in enumerate(findings):
        if conflict == 'estimate':
            TimeEstimate.create(finding_id=finding.id, variant_id=variant.id,
                                optimistic=index + 1, likely=2, pessimistic=3)
        else:
            db.session.add(AssessmentReview(
                assessment_id=assessment.id, variant_id=variant.id, finding_id=finding.id,
                status='affected', rationale=f'Independent analyst rationale {index}',
            ))
    db.session.commit()
    with pytest.raises(ValueError, match='Resolve the duplicate records before retrying'):
        with db.session.begin_nested():
            consolidate_jsonld_packages(db.session())
    db.session.expire_all()
    assert len(Package.get_all()) == len(Finding.get_all()) == 3
    assert Package.get_by_string_id('mbedtls@') is not None
    assert Package.get_by_string_id('mbedtls@4.1.1') is None
    assert db.session.query(AssessmentReview if conflict == 'review' else TimeEstimate).count() == 3


@pytest.mark.parametrize('name,version,purl,cpe,release', [
    ('zephyr', '4.5.0-rc2', None, 'cpe:2.3:o:zephyrproject:zephyr:4.5.0:rc2:*:*:*:*:*:*', '4.5.0-rc2'),
    ('hostap', 'a' * 40, 'pkg:generic/hostap@hostap_2_11?vcs_url=git://w1.fi/hostap.git',
     'cpe:2.3:a:w1.fi:hostapd:2.11:*:*:*:*:*:*:*', '2.11'),
    ('trusted-firmware-m', 'a' * 40,
     'pkg:generic/trusted-firmware-m@TF-Mv2.3.1'
     '?vcs_url=git%2Bhttps://review.trustedfirmware.org/TF-M/trusted-firmware-m',
     'cpe:2.3:o:arm:trusted_firmware-m:2.3.1:-:*:*:*:*:*:*', '2.3.1'),
])
def test_equivalent_zephyr_version_spellings_agree_in_stored_packages_and_graphs(
        app, tmp_path, name, version, purl, cpe, release):
    revision = 'a' * 40
    namespace = 'https://example.org/zephyr/'
    upstream_ref = namespace + name + '-deps'
    source_ref = namespace + name + '-sources'
    document = _zephyr_spdx3([
        {'type': 'software_Package', 'spdxId': upstream_ref, 'name': name + '-deps',
         'software_packageVersion': version,
         'software_downloadLocation': f'git+https://example.org/{name}@{revision}',
         'externalIdentifier': [
             {'externalIdentifierType': 'cpe23', 'identifier': cpe},
             *([{'externalIdentifierType': 'packageUrl', 'identifier': purl}] if purl else []),
         ]},
        {'type': 'software_Package', 'spdxId': source_ref, 'name': name + '-sources',
         'software_packageVersion': revision, 'software_primaryPurpose': 'source'},
        {'type': 'Relationship', 'relationshipType': 'hasVariant', 'from': upstream_ref, 'to': [source_ref]},
    ])
    variant_id, _ = _scan(app, tmp_path, name, document)
    client = app.test_client()
    rows = client.get(f'/api/packages?variant_id={variant_id}').json
    assert len(rows) == len(Package.get_all()) == 1
    upstream = rows[0]
    assert upstream['release_version'] == release
    assert upstream['source_revision'] == revision
    assert not upstream['version_conflict']
    assert upstream['version'] == release
    assert upstream['id'] == f'{name}@{release}'
    assert 'jsonld_group' not in upstream
    graph_packages = client.get(f'/api/package-dependencies?variant_id={variant_id}').json['documents'][0]['packages']
    graph_upstream = next(package for package in graph_packages if package['id'] == upstream['id'])
    assert graph_upstream['release_version'] == release
    assert graph_upstream['version_evidence'] == upstream['version_evidence']
    assert graph_upstream['source_revision'] == revision
    assert not graph_upstream['version_conflict']


def test_jsonld_components_are_one_stored_package_and_survive_input_cleanup(app, tmp_path):
    project = Project.create('grouping')
    variant = Variant.create('demo', project.id)
    scan = _import_grouping_documents(tmp_path, variant, _grouping_documents())
    rows = app.test_client().get(f'/api/packages?variant_id={variant.id}').json
    assert len(rows) == len(Package.get_all()) == 1
    assert rows[0]['id'] == 'mbedtls@4.1.1'
    assert rows[0]['source_revision'] == 'a' * 40
    assert rows[0]['source_revisions'] == ['a' * 40]
    assert 'jsonld_group' not in rows[0]
    for document in SBOMDocument.get_by_scan(scan.id):
        Path(document.path).unlink()
    assert app.test_client().get(f'/api/packages?variant_id={variant.id}').json == rows
    assert len(Package.get_all()) == 1


def test_cli_and_queued_scanners_use_the_actual_stored_parent(app, tmp_path):
    from src.bin.cmd_vuln_scan import _resolve_active_packages
    from src.controllers.scan_jobs import _variant_sbom_packages
    from src.routes._scan_helpers import resolve_active_packages

    project = Project.create('logical-scans')
    variant = Variant.create('demo', project.id)
    _import_grouping_documents(tmp_path, variant, _grouping_documents())
    assert len(Package.get_all()) == 1
    component = Package.get_by_string_id('mbedtls@4.1.1')
    assert component.name == 'mbedtls'
    assert component.version == '4.1.1'
    assert Package.get_by_string_id('mbedtls-deps@' + 'a' * 40) is None
    assert Package.get_by_string_id('mbedtls-sources@' + 'a' * 40) is None
    assert component.cpe[0] == 'cpe:2.3:a:trustedfirmware:mbed_tls:4.1.1:*:*:*:*:*:*:*'
    assert 'pkg:github/mbed-tls/mbedtls@v4.1.1' in component.purl
    queued, error = resolve_active_packages(variant.id)
    assert error is None
    assert [package.to_dict() for package in queued] == [component.to_dict()]
    assert [package.to_dict() for package in _resolve_active_packages(variant.id)] == [component.to_dict()]
    assert _variant_sbom_packages(variant.id) == {('mbedtls', '4.1.1')}
    db.session.expire_all()
    assert len(Package.get_all()) == 1


def test_ordinary_export_uses_stored_parent_and_canonical_dependencies(app, tmp_path):
    from src.helpers.export_scope import compute_export_scope
    from src.views.cyclonedx import CycloneDx

    documents = _grouping_documents()
    documents['upstream']['@graph'].extend([
        {'type': 'software_Package', 'spdxId': 'https://example.org/zephyr/crypto',
         'name': 'crypto', 'software_packageVersion': '1'},
        {'type': 'Relationship', 'relationshipType': 'dependsOn',
         'from': 'https://example.org/zephyr/source', 'to': ['https://example.org/zephyr/crypto']},
        {'type': 'Relationship', 'relationshipType': 'dependsOn',
         'from': 'https://example.org/zephyr/upstream', 'to': ['https://example.org/zephyr/source']},
    ])
    project = Project.create('logical-export')
    variant = Variant.create('demo', project.id)
    _import_grouping_documents(tmp_path, variant, documents)
    controllers = ControllersCache(scope=compute_export_scope(variant_id=variant.id))
    controllers.packages._preload_cache()
    assert len(controllers.packages) == 2
    assert controllers.packages.get('mbedtls@4.1.1').string_id == 'mbedtls@4.1.1'
    assert controllers.packages.get('mbedtls-sources@' + 'a' * 40) is None
    assert controllers.packages.dependency_edges() == {('mbedtls@4.1.1', 'crypto@1')}
    exported = json.loads(CycloneDx(controllers).output_as_json(6))
    assert {(component['name'], component['version']) for component in exported['components']} == {
        ('mbedtls', '4.1.1'), ('crypto', '1'),
    }
    exported_component = next(component for component in exported['components'] if component['name'] == 'mbedtls')
    assert exported_component['purl'] == 'pkg:github/mbed-tls/mbedtls@v4.1.1'
    refs = {component['bom-ref'] for component in exported['components']}
    assert all(dependency['ref'] in refs and set(dependency.get('dependsOn', [])).issubset(refs)
               for dependency in exported['dependencies'])


@pytest.mark.parametrize('artifact_purl', [
    'pkg:github/mbed-tls/mbedtls@v4.1.1', 'pkg:generic/mbedtls@4.1.1',
])
def test_grype_results_use_the_stored_parent_without_alias_translation(app, tmp_path, artifact_purl):
    from unittest.mock import Mock
    from src.models import Observation, Vulnerability
    from src.views.grype_vulns import GrypeVulns
    from src.controllers.scan_jobs import _filter_grype_matches
    from src.routes._scan_diff import _global_result_full, _serialize_list_with_diff

    project = Project.create('logical-grype')
    variant = Variant.create('demo', project.id)
    sbom = _import_grouping_documents(tmp_path, variant, _grouping_documents())
    parent = Package.get_by_string_id('mbedtls@4.1.1')
    legacy = Vulnerability.create_record(id='CVE-2026-1000')
    finding = Finding.get_or_create(parent.id, legacy.id)
    Observation.create(finding_id=finding.id, scan_id=sbom.id)
    tool = Scan.create('Grype', variant.id, scan_type='tool', scan_source='grype')
    controllers = ControllersCache()
    controllers.assessments.current_variant_id = variant.id
    controllers.vulnerabilities.current_variant_id = variant.id
    controllers.packages.current_sbom_document = SBOMDocument.create('grype.json', 'grype', tool.id, format='grype')
    grype_data = {'matches': [{
        'artifact': {'name': 'trustedfirmware/mbedtls', 'version': '4.1.1',
                     'purl': artifact_purl},
        'vulnerability': {'id': 'CVE-2026-1001'},
    }]}
    results_path = tmp_path / 'grype.json'
    results_path.write_text(json.dumps(grype_data))
    _filter_grype_matches(Mock(), str(results_path), {('mbedtls', '4.1.1')})
    assert json.loads(results_path.read_text()) == grype_data
    GrypeVulns(controllers).load_from_dict(grype_data)
    db.session.commit()
    grype_finding = next(finding for finding in Finding.get_all() if finding.vulnerability_id == 'CVE-2026-1001')
    assert grype_finding.package_id == parent.id
    Observation.create(finding_id=grype_finding.id, scan_id=tool.id)
    assert len(Package.get_all()) == 1
    scans = Scan.get_all()
    history = _serialize_list_with_diff(scans)
    assert history[0]['package_count'] == 1
    assert history[1]['global_package_count'] == 1
    assert history[1]['branch_package_count'] == 1
    result = _global_result_full(tool, scans)
    assert result['package_count'] == len(result['packages']) == 1
    assert result['packages'][0]['package_name'] == 'mbedtls'
    assert result['packages'][0]['package_version'] == '4.1.1'
    assert {entry['vulnerability_id'] for entry in result['findings']} == {'CVE-2026-1000', 'CVE-2026-1001'}
    assert app.test_client().get(f'/api/scans/{sbom.id}/diff').json['package_count'] == 1


def test_logical_scan_history_compares_components_not_each_original_entry(app, tmp_path):
    from src.routes._scan_diff import _serialize_list_with_diff

    project = Project.create('logical-history')
    variant = Variant.create('demo', project.id)
    first = _import_grouping_documents(tmp_path, variant, _grouping_documents())
    second = _import_grouping_documents(tmp_path, variant, _grouping_documents())
    upgraded_documents = json.loads(json.dumps(_grouping_documents('b' * 40)).replace('4.1.1', '4.2.0'))
    third = _import_grouping_documents(tmp_path, variant, upgraded_documents)
    history = _serialize_list_with_diff([first, second, third])
    assert [entry['package_count'] for entry in history] == [1, 1, 1]
    assert history[1]['packages_unchanged'] == 1
    assert history[2]['packages_upgraded'] == 1
    assert history[2]['packages_added'] == history[2]['packages_removed'] == 0
    client = app.test_client()
    unchanged = client.get(f'/api/scans/{second.id}/diff').json
    assert unchanged['packages_unchanged'][0]['package_version'] == '4.1.1'
    upgraded = client.get(f'/api/scans/{third.id}/diff').json
    assert upgraded['package_count'] == 1
    assert len(upgraded['packages_upgraded']) == 1
    assert upgraded['packages_upgraded'][0]['package_name'] == 'mbedtls'
    assert upgraded['packages_upgraded'][0]['old_version'] == '4.1.1'
    assert upgraded['packages_upgraded'][0]['new_version'] == '4.2.0'


def test_cli_osv_queries_all_parent_identifiers_and_persists_one_finding(app, tmp_path, monkeypatch):
    from unittest.mock import Mock

    project = Project.create('logical-osv')
    variant = Variant.create('demo', project.id)
    _import_grouping_documents(tmp_path, variant, _grouping_documents())
    component = Package.get_by_string_id('mbedtls@4.1.1')
    client = Mock()
    client.query_by_purl.return_value = [{'id': 'CVE-2026-1002'}]
    monkeypatch.setattr('src.bin.cmd_vuln_scan.OSVClient', lambda: client)
    result = app.test_cli_runner().invoke(args=['osv-scan', '--project', project.name, '--variant', variant.name])
    assert result.exit_code == 0, result.output
    assert {call.args[0] for call in client.query_by_purl.call_args_list} == set(component.purl)
    findings = [finding for finding in Finding.get_all() if finding.vulnerability_id == 'CVE-2026-1002']
    assert len(findings) == 1
    assert findings[0].package_id == component.id


@pytest.mark.parametrize('selected', ['first', 'second'])
def test_cli_osv_uses_only_active_variant_identifiers(app, tmp_path, monkeypatch, selected):
    from unittest.mock import Mock
    from src.models import Observation
    from src.models.assessment_target import AssessmentTarget

    project = Project.create('scoped-osv')
    variants = {name: Variant.create(name, project.id) for name in ('first', 'second')}
    _import_grouping_documents(tmp_path, variants['first'], _grouping_documents())
    purls = {'first': 'pkg:pypi/mbedtls@4.1.1', 'second': 'pkg:generic/mbedtls@4.1.1'}
    for name, revision in (('first', 'b' * 40), ('second', 'c' * 40)):
        documents = _grouping_documents(revision)
        documents['upstream']['@graph'][-1]['externalIdentifier'][0]['identifier'] = purls[name]
        _import_grouping_documents(tmp_path, variants[name], documents)
    component = Package.get_by_string_id('mbedtls@4.1.1')
    component.purl = [*component.purl, 'pkg:npm/mbedtls@4.1.1']
    db.session.commit()
    assert set(component.purl) > set(purls.values())
    revision = ('b' if selected == 'first' else 'c') * 40
    expected_purls = {
        purls[selected], 'pkg:generic/mbedtls',
        f'pkg:generic/mbedtls-deps@{revision}', f'pkg:generic/mbedtls-sources@{revision}',
    }
    client = Mock()
    client.query_by_purl.side_effect = lambda purl: [
        {'id': 'CVE-2026-2001' if purl in expected_purls else 'CVE-2026-2002'},
    ]
    monkeypatch.setattr('src.bin.cmd_vuln_scan.OSVClient', lambda: client)
    result = app.test_cli_runner().invoke(args=[
        'osv-scan', '--project', project.name, '--variant', variants[selected].name,
    ])
    assert result.exit_code == 0, result.output
    assert {call.args[0] for call in client.query_by_purl.call_args_list} == expected_purls
    assert client.query_by_purl.call_count == len(expected_purls)
    assert {(finding.package_id, finding.vulnerability_id) for finding in Finding.get_all()} == {
        (component.id, 'CVE-2026-2001'),
    }
    assert {(observation.scan.variant_id, observation.finding.package_id)
            for observation in db.session.query(Observation)} == {(variants[selected].id, component.id)}
    assert {(target.variant_id, target.finding.package_id)
            for target in db.session.query(AssessmentTarget)} == {(variants[selected].id, component.id)}


def test_reimporting_companions_reuses_one_real_parent_uuid(app, tmp_path):
    project = Project.create('batched-history')
    variant = Variant.create('demo', project.id)
    scans = [_import_grouping_documents(tmp_path, variant, _grouping_documents()) for _ in range(5)]
    assert len(Package.get_all()) == 1
    parent = Package.get_by_string_id('mbedtls@4.1.1')
    assert {link.package_id for link in db.session.query(SBOMPackage).all()} == {parent.id}
    assert len({link.sbom_document_id for link in db.session.query(SBOMPackage).all()}) == len(scans) * 3


@pytest.mark.parametrize('collision', ['another-group', 'ordinary-package'])
def test_same_parent_identity_is_reused_across_documents_and_variants(app, tmp_path, collision):
    from src.helpers.export_scope import compute_export_scope

    project = Project.create('ambiguous-components')
    variant = Variant.create('first', project.id)
    documents = _grouping_documents()
    documents.pop('build')
    first = _import_grouping_documents(tmp_path, variant, documents)
    if collision == 'another-group':
        second_variant = Variant.create('second', project.id)
        documents = _grouping_documents('b' * 40)
        documents.pop('build')
        second = _import_grouping_documents(tmp_path, second_variant, documents)
    else:
        document = SBOMDocument.create('ordinary.json', 'ordinary', first.id, format='cdx')
        SBOMPackage.create(document.id, Package.find_or_create('mbedtls', '4.1.1').id)
    assert len(Package.get_all()) == 1
    rows = app.test_client().get(f'/api/packages?project_id={project.id}').json
    assert all('jsonld_group' not in row for row in rows)
    controllers = ControllersCache(scope=compute_export_scope(project_id=project.id))
    controllers.packages._preload_cache()
    assert len(controllers.packages) == 1


@pytest.mark.parametrize('change', ['no-relationship', 'other-producer', 'conflicting-revision', 'conflicting-release'])
def test_jsonld_groups_require_provenance_and_consistent_versions(app, tmp_path, change):
    documents = _grouping_documents()
    if change == 'no-relationship':
        documents['sources']['@graph'] = [
            item for item in documents['sources']['@graph'] if item.get('relationshipType') != 'hasVariant'
        ]
    elif change == 'other-producer':
        for document in documents.values():
            for item in document['@graph']:
                if item.get('type') == 'SoftwareAgent':
                    item['name'] = 'Another generator'
    elif change == 'conflicting-revision':
        documents['upstream']['@graph'][-1]['software_packageVersion'] = 'b' * 40
    else:
        documents['upstream']['@graph'][-1]['externalIdentifier'][0]['identifier'] = 'pkg:github/Mbed-TLS/mbedtls@v5.0.0'
    project = Project.create('not-grouped')
    variant = Variant.create('demo', project.id)
    _import_grouping_documents(tmp_path, variant, documents)
    rows = app.test_client().get(f'/api/packages?variant_id={variant.id}').json
    assert all('jsonld_group' not in row for row in rows)
    assert len(rows) == len(Package.get_all()) == (2 if change == 'other-producer' else 3)


def test_jsonld_sources_without_build_provenance_do_not_absorb_a_same_named_target(app, tmp_path):
    documents = _grouping_documents()
    documents['build']['@graph'] = [item for item in documents['build']['@graph']
                                   if item.get('relationshipType') != 'hasInput']
    project = Project.create('workspace-only')
    variant = Variant.create('demo', project.id)
    _import_grouping_documents(tmp_path, variant, documents)
    rows = app.test_client().get(f'/api/packages?variant_id={variant.id}').json
    assert len(rows) == len(Package.get_all()) == 2
    target = next(row for row in rows if row['id'] == 'mbedtls@')
    assert 'jsonld_group' not in target
    parent = next(row for row in rows if row['id'] == 'mbedtls@4.1.1')
    assert parent['source_revision'] == 'a' * 40


def test_jsonld_ambiguous_build_ownership_keeps_original_records(app, tmp_path):
    documents = _grouping_documents()
    documents['build']['@graph'].extend([
        {'type': 'software_Package', 'spdxId': 'https://example.org/zephyr/other-target', 'name': 'mbedtls',
         'software_packageVersion': 'other'},
        {'type': 'Relationship', 'relationshipType': 'contains',
         'from': 'https://example.org/zephyr/other-target', 'to': ['https://example.org/zephyr/library']},
    ])
    project = Project.create('ambiguous-build')
    variant = Variant.create('demo', project.id)
    _import_grouping_documents(tmp_path, variant, documents)
    rows = app.test_client().get(f'/api/packages?variant_id={variant.id}').json
    assert all('jsonld_group' not in row for row in rows)


def test_jsonld_parent_revisions_remain_scoped_and_yocto_is_not_rewritten(app, tmp_path):
    project = Project.create('mixed')
    first = Variant.create('one', project.id)
    _import_grouping_documents(tmp_path, first, _grouping_documents())
    second = Variant.create('two', project.id)
    _import_grouping_documents(tmp_path, second, _grouping_documents('b' * 40))
    client = app.test_client()
    assert all('jsonld_group' not in row for row in client.get(f'/api/packages?project_id={project.id}').json)
    assert client.get(f'/api/packages?variant_id={first.id}').json[0]['source_revision'] == 'a' * 40
    assert client.get(f'/api/packages?variant_id={second.id}').json[0]['source_revision'] == 'b' * 40
    scan = Scan.get_by_variant_id(first.id)[-1]
    document = SBOMDocument.create('yocto.json', 'yocto.json', scan.id, format='yocto_cve_check')
    package = Package.find_or_create('mbedtls-sources', 'ordinary-yocto-version')
    SBOMPackage.create(document.id, package.id)
    assert all('jsonld_group' not in row for row in client.get(f'/api/packages?variant_id={first.id}').json)
    assert Package.get_by_string_id('mbedtls-sources@ordinary-yocto-version') is not None


def test_jsonld_group_migration_preserves_existing_documents_without_guessing(app, tmp_path):
    from importlib import import_module
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    project = Project.create('legacy-grouping')
    variant = Variant.create('demo', project.id)
    _import_grouping_documents(tmp_path, variant, _grouping_documents())
    variant_id = variant.id
    db.session.remove()
    migration = import_module('src.migrations.versions.d8f63a29b104_add_scoped_package_types')
    with db.engine.begin() as connection:
        with Operations.context(MigrationContext.configure(connection)):
            migration.downgrade()
            assert 'jsonld_groups' not in {column['name'] for column in inspect(connection).get_columns('sbom_documents')}
            migration.upgrade()
        assert list(connection.execute(text('SELECT jsonld_groups FROM sbom_documents')).scalars()) == [None] * 3
    rows = app.test_client().get(f'/api/packages?variant_id={variant_id}').json
    assert all('jsonld_group' not in row for row in rows)


def test_zephyr_companion_documents_preserve_versions_and_build_dependencies(app, tmp_path):
    revision = 'a' * 40
    release_purl = 'pkg:github/Mbed-TLS/mbedtls@v4.1.1'
    release_cpe = 'cpe:2.3:a:trustedfirmware:mbed_tls:4.1.1:*:*:*:*:*:*:*'
    documents = {
        'app': _zephyr_spdx3([
            {'type': 'software_Package', 'spdxId': 'zephyr:packages/app-sources',
             'name': 'app-sources', 'software_primaryPurpose': 'source'},
        ]),
        'build': _zephyr_spdx3([
            *({'type': 'software_Package', 'spdxId': f'zephyr:packages/{name}',
               'name': name, 'software_primaryPurpose': 'library'}
              for name in ('app', 'mbedtls', 'tfpsacrypto')),
            {'type': 'Relationship', 'relationshipType': 'hasPrerequisite',
             'from': 'zephyr:packages/app', 'to': ['zephyr:packages/mbedtls']},
            {'type': 'Relationship', 'relationshipType': 'hasPrerequisite',
             'from': 'zephyr:packages/mbedtls', 'to': ['zephyr:packages/tfpsacrypto']},
            {'type': 'Relationship', 'relationshipType': 'contains',
             'from': 'zephyr:packages/app', 'to': ['zephyr:files/libapp.a']},
            {'type': 'software_File', 'spdxId': 'zephyr:files/libapp.a', 'name': 'libapp.a'},
            {'type': 'Relationship', 'relationshipType': 'hasStaticLink',
             'from': 'zephyr:files/libapp.a', 'to': ['zephyr:files/libmbedtls.a']},
        ]),
        'modules-deps': _zephyr_spdx3([
            *({'type': 'software_Package', 'spdxId': f'zephyr:packages/{name}-deps',
               'name': f'{name}-deps', 'software_packageVersion': revision,
               'software_primaryPurpose': 'library',
               'externalIdentifier': [
                   {'type': 'ExternalIdentifier', 'externalIdentifierType': 'packageUrl',
                    'identifier': release_purl},
                   {'type': 'ExternalIdentifier', 'externalIdentifierType': 'cpe23',
                    'identifier': release_cpe},
               ] if name == 'mbedtls' else []}
              for name in ('zephyr', 'mbedtls')),
            {'type': 'Relationship', 'relationshipType': 'dependsOn',
             'from': 'zephyr:packages/zephyr-deps', 'to': ['zephyr:packages/mbedtls-deps']},
        ]),
        'zephyr': _zephyr_spdx3([
            {'type': 'software_Package', 'spdxId': 'zephyr:packages/mbedtls-sources',
             'name': 'mbedtls-sources', 'software_packageVersion': revision,
             'software_primaryPurpose': 'source'},
            {'type': 'Relationship', 'relationshipType': 'hasVariant',
             'from': 'zephyr:packages/mbedtls-deps', 'to': ['zephyr:packages/mbedtls-sources']},
        ]),
    }
    with app.app_context():
        project = Project.create('zephyr')
        variant = Variant.create('demo', project.id)
        variant_id = variant.id
        scan = Scan.create('SBOM', variant.id)
        scan_id = scan.id
        for name, document in documents.items():
            path = tmp_path / f'{name}.jsonld'
            path.write_text(json.dumps(document))
            SBOMDocument.create(str(path), path.name, scan.id, format='spdx')
        read_inputs(ControllersCache(), scan.id)
        assert len(Package.get_all()) == 6
        module = Package.get_by_string_id('mbedtls@4.1.1')
        assert module.version == '4.1.1'
        assert 'pkg:github/mbed-tls/mbedtls@v4.1.1' in module.purl
        assert release_cpe in module.cpe
        assert Package.get_by_string_id('mbedtls@').version == ''
        assert Package.get_by_string_id(f'mbedtls-sources@{revision}') is None
        assert Package.get_by_string_id(f'mbedtls-deps@{revision}') is None

    client = app.test_client()
    response = client.get(f'/api/package-dependencies?variant_id={variant_id}')
    assert response.status_code == 200
    graphs = {document['source_name']: document for document in response.json['documents']}
    assert {name: len(graph['packages']) for name, graph in graphs.items()} == {
        'app.jsonld': 1, 'build.jsonld': 3, 'modules-deps.jsonld': 2, 'zephyr.jsonld': 1,
    }
    assert graphs['build.jsonld']['edges'] == [
        {'package_id': 'app@', 'dependency_id': 'mbedtls@'},
        {'package_id': 'mbedtls@', 'dependency_id': 'tfpsacrypto@'},
    ]
    assert graphs['modules-deps.jsonld']['edges'] == [
        {'package_id': f'zephyr-deps@{revision}', 'dependency_id': 'mbedtls@4.1.1'},
    ]
    module_graph = next(package for package in graphs['modules-deps.jsonld']['packages']
                        if package['name'] == 'mbedtls')
    assert module_graph['version'] == '4.1.1'
    assert module_graph['source_revision'] == revision
    assert module_graph['release_version'] == '4.1.1'
    package_response = client.get(f'/api/packages?variant_id={variant_id}&format=list')
    assert package_response.status_code == 200
    module_api = next(package for package in package_response.json if package['id'] == 'mbedtls@4.1.1')
    assert module_api['release_version'] == '4.1.1'
    assert module_api['source_revision'] == revision
    assert module_api['id'] == 'mbedtls@4.1.1'
    assert {item['source'] for item in module_api['version_evidence']} == {'sbom', 'purl', 'cpe'}
    assert graphs['app.jsonld']['edges'] == graphs['zephyr.jsonld']['edges'] == []
    assert client.get(f'/api/package-dependencies?variant_id={variant_id}&counts=1').json['counts'] == {
        'app@': {'in': 1, 'out': 0}, 'mbedtls@': {'in': 1, 'out': 1}, 'tfpsacrypto@': {'in': 0, 'out': 1},
        f'zephyr-deps@{revision}': {'in': 1, 'out': 0}, 'mbedtls@4.1.1': {'in': 0, 'out': 1},
    }
    with app.app_context():
        read_inputs(ControllersCache(), scan_id)
        assert db.session.query(PackageDependency).count() == 3


@pytest.mark.parametrize('reverse', [False, True])
@pytest.mark.parametrize('source_ref', ['zephyr:packages/app', 'app-ref'])
def test_spdx3_dependencies_resolve_namespaces_and_companion_documents(app, tmp_path, reverse, source_ref):
    documents = {
        'app': _zephyr_spdx3([
            {'type': 'software_Package', 'spdxId': source_ref, 'name': 'app'},
            {'type': 'LifecycleScopedRelationship', 'scope': 'build', 'relationshipType': 'hasPrerequisite',
             'from': source_ref, 'to': ['https://example.org/zephyr/packages/lib']},
            {'type': 'Relationship', 'relationshipType': 'dependsOn', 'from': source_ref,
             'to': ['zephyr:packages/missing']},
        ]),
        'lib': _zephyr_spdx3([
            {'type': 'software_Package', 'spdxId': 'companion:packages/lib', 'name': 'lib'},
            {'type': 'Relationship', 'relationshipType': 'dependencyOf',
             'from': 'companion:packages/lib', 'to': ['companion:packages/app']},
        ], prefix='companion'),
    }
    with app.app_context():
        project = Project.create('cross-document')
        variant = Variant.create('demo', project.id)
        variant_id = variant.id
        scan = Scan.create('SBOM', variant.id)
        scan_id = scan.id
        for name in sorted(documents, reverse=reverse):
            path = tmp_path / f'{name}.jsonld'
            path.write_text(json.dumps(documents[name]))
            SBOMDocument.create(str(path), path.name, scan.id, format='spdx')
        read_inputs(ControllersCache(), scan.id)
        rows = db.session.execute(
            db.select(SBOMDocument.source_name, PackageDependency.package_id, PackageDependency.dependency_id)
            .join(SBOMDocument, SBOMDocument.id == PackageDependency.sbom_document_id)
        ).all()
        names = {package.id: package.name for package in Package.get_all()}
        assert [(source, names[package], names[dependency]) for source, package, dependency in rows] == [
            ('app.jsonld', 'app', 'lib'),
        ]

    client = app.test_client()
    assert client.get(f'/api/package-dependencies?variant_id={variant_id}&counts=1').json['counts'] == {
        'app@': {'in': 1, 'out': 0}, 'lib@': {'in': 0, 'out': 1},
    }
    graphs = {document['source_name']: document for document in client.get(
        f'/api/package-dependencies?variant_id={variant_id}'
    ).json['documents']}
    assert graphs['app.jsonld']['edges'] == [{'package_id': 'app@', 'dependency_id': 'lib@'}]
    assert graphs['lib.jsonld']['edges'] == []

    for name, document in documents.items():
        document['@graph'] = [item for item in document['@graph'] if 'relationshipType' not in item]
        (tmp_path / f'{name}.jsonld').write_text(json.dumps(document))
    with app.app_context():
        read_inputs(ControllersCache(), scan_id)
        assert db.session.query(PackageDependency).count() == 0


def test_spdx3_uri_references_do_not_leak_across_scans_or_namespaces(app, tmp_path):
    with app.app_context():
        project = Project.create('isolated')
        for name, namespace, packages in (
            ('other-scan', 'https://example.org/zephyr/', ('lib',)),
            ('current-scan', 'https://example.org/unrelated/', ('lib',)),
        ):
            variant = Variant.create(name, project.id)
            scan = Scan.create('SBOM', variant.id)
            path = tmp_path / f'{name}.jsonld'
            path.write_text(json.dumps(_zephyr_spdx3([
                {'type': 'software_Package', 'spdxId': f'zephyr:packages/{package}',
                 'name': f'{name}-{package}'} for package in packages
            ], namespace=namespace)))
            SBOMDocument.create(str(path), path.name, scan.id, format='spdx')
        path = tmp_path / 'dependent.jsonld'
        path.write_text(json.dumps(_zephyr_spdx3([
            {'type': 'software_Package', 'spdxId': 'zephyr:packages/app', 'name': 'app'},
            {'type': 'Relationship', 'relationshipType': 'dependsOn',
             'from': 'zephyr:packages/app', 'to': ['zephyr:packages/lib']},
        ])))
        SBOMDocument.create(str(path), path.name, scan.id, format='spdx')
        read_inputs(ControllersCache())
        assert db.session.query(PackageDependency).count() == 0


@pytest.mark.parametrize('namespace_map', [None, 123, 'invalid'])
def test_invalid_spdx3_namespace_map_keeps_local_dependencies(app, tmp_path, caplog, namespace_map):
    document = _spdx3()
    document['@graph'].append({'type': 'SpdxDocument', 'namespaceMap': namespace_map})
    variant_id, _ = _scan(app, tmp_path, 'invalid-map', document)
    graph = app.test_client().get(f'/api/package-dependencies?variant_id={variant_id}').json['documents'][0]
    assert len(graph['edges']) == 3
    assert 'Skipping invalid SPDX namespaceMap' in caplog.text


def _yocto_spdx2(name, packages=(), refs=(), relationships=()):
    """Build one per-recipe/per-package document of a Yocto SPDX 2.2 archive."""
    return {
        'spdxVersion': 'SPDX-2.2', 'SPDXID': 'SPDXRef-DOCUMENT', 'name': name, 'dataLicense': 'CC0-1.0',
        'documentNamespace': f'http://spdx.org/spdxdocs/{name}',
        'creationInfo': {'creators': ['Tool: test'], 'created': '2024-01-01T00:00:00Z'},
        'externalDocumentRefs': [
            {'externalDocumentId': ref, 'spdxDocument': f'http://spdx.org/spdxdocs/{target}',
             'checksum': {'algorithm': 'SHA1', 'checksumValue': '0' * 40}}
            for ref, target in refs
        ],
        'packages': [{'SPDXID': spdx_id, 'name': package, 'versionInfo': '1.0', 'downloadLocation': 'NOASSERTION'}
                     for spdx_id, package in packages],
        'relationships': [{'spdxElementId': source, 'relationshipType': kind, 'relatedSpdxElement': target}
                          for source, kind, target in relationships],
    }


def _yocto_archive():
    return {
        'runtime-app': _yocto_spdx2('runtime-app', refs=(
            ('DocumentRef-app', 'recipe-app'), ('DocumentRef-util', 'util'), ('DocumentRef-ghost', 'ghost'),
        ), relationships=(
            ('DocumentRef-util:SPDXRef-Package-util', 'RUNTIME_DEPENDENCY_OF', 'DocumentRef-app:SPDXRef-Recipe-app'),
            ('DocumentRef-ghost:SPDXRef-Package-ghost', 'RUNTIME_DEPENDENCY_OF', 'DocumentRef-app:SPDXRef-Recipe-app'),
            ('DocumentRef-unknown:SPDXRef-Package-x', 'RUNTIME_DEPENDENCY_OF', 'DocumentRef-app:SPDXRef-Recipe-app'),
        )),
        'recipe-app': _yocto_spdx2('recipe-app', packages=(('SPDXRef-Recipe-app', 'app'),), refs=(
            ('DocumentRef-dependency-recipe-lib', 'recipe-lib'),
        ), relationships=(
            ('DocumentRef-dependency-recipe-lib:SPDXRef-Recipe-lib', 'BUILD_DEPENDENCY_OF', 'SPDXRef-Recipe-app'),
        )),
        'recipe-lib': _yocto_spdx2('recipe-lib', packages=(('SPDXRef-Recipe-lib', 'lib'),)),
        'util': _yocto_spdx2('util', packages=(('SPDXRef-Package-util', 'util'),)),
    }


@pytest.mark.parametrize('ignore_parsing_errors', ['false', 'true'])
@pytest.mark.parametrize('reverse', [False, True])
def test_yocto_spdx2_source_revisions_resolve_recipes_without_toolchain_contamination(
        app, tmp_path, monkeypatch, ignore_parsing_errors, reverse):
    monkeypatch.setenv('IGNORE_PARSING_ERRORS', ignore_parsing_errors)
    revision, compiler_revision = 'a' * 40, 'b' * 40
    url = f'git+https://example.org/glibc.git@{revision}'
    recipe = _yocto_spdx2('recipe-glibc', packages=(
        ('SPDXRef-Recipe-glibc', 'glibc'), ('SPDXRef-Download-glibc', 'glibc-source'),
    ), refs=(('DocumentRef-compiler', 'recipe-compiler'),), relationships=(
        ('SPDXRef-Download-glibc', 'BUILD_DEPENDENCY_OF', 'SPDXRef-Recipe-glibc'),
        ('DocumentRef-compiler:SPDXRef-Recipe-compiler', 'BUILD_DEPENDENCY_OF', 'SPDXRef-Recipe-glibc'),
    ))
    recipe['packages'][0]['versionInfo'] = '2.41+git'
    recipe['packages'][1].pop('versionInfo')
    recipe['packages'][1]['downloadLocation'] = url
    binary = _yocto_spdx2('libc6', packages=(('SPDXRef-Package-libc6', 'libc6'),),
                         refs=(('DocumentRef-glibc', 'recipe-glibc'),), relationships=(
                             ('SPDXRef-Package-libc6', 'GENERATED_FROM',
                              'DocumentRef-glibc:SPDXRef-Recipe-glibc'),
                         ))
    binary['packages'][0]['versionInfo'] = '2.41+git'
    binary['packages'][0]['checksums'] = [{'algorithm': 'SHA1', 'checksumValue': 'f' * 40}]
    compiler = _yocto_spdx2('recipe-compiler', packages=(
        ('SPDXRef-Recipe-compiler', 'compiler'), ('SPDXRef-Download-compiler', 'compiler-source'),
    ), relationships=(('SPDXRef-Download-compiler', 'BUILD_DEPENDENCY_OF', 'SPDXRef-Recipe-compiler'),))
    compiler['packages'][1].pop('versionInfo')
    compiler['packages'][1]['downloadLocation'] = f'git+https://example.org/compiler.git@{compiler_revision}'
    unrelated = _yocto_spdx2('other-libc', packages=(('SPDXRef-other', 'other-libc'),),
                            refs=(('DocumentRef-glibc', 'recipe-glibc'),), relationships=(
                                ('SPDXRef-other', 'GENERATED_FROM', 'DocumentRef-glibc:SPDXRef-Recipe-glibc'),
                            ))
    with app.app_context():
        project = Project.create('yocto-source')
        variant = Variant.create('default', project.id)
        scan = Scan.create('SBOM', variant.id)
        scan_id, variant_id = scan.id, variant.id
        documents = [('recipe', recipe), ('binary', binary), ('compiler', compiler)]
        for name, document in reversed(documents) if reverse else documents:
            path = tmp_path / f'{name}.spdx.json'
            path.write_text(json.dumps(document))
            SBOMDocument.create(str(path), path.name, scan.id, format='spdx')
        other_variant = Variant.create('other', project.id)
        other_scan = Scan.create('SBOM', other_variant.id)
        path = tmp_path / 'other.spdx.json'
        path.write_text(json.dumps(unrelated))
        SBOMDocument.create(str(path), path.name, other_scan.id, format='spdx')
        read_inputs(ControllersCache())
        db.session.remove()
        libc = _package_in_scan(scan_id, 'libc6@2.41')
        assert libc.source_urls == [url]
        assert libc.version_info['release_version'] == '2.41'
        assert libc.version_info['source_revision'] == revision
        assert not libc.version_info['revision_conflict']
        assert _package_in_scan(scan_id, 'glibc@2.41').source_urls == [url]
        assert _package_in_scan(scan_id, 'compiler@1.0').version_info['source_revision'] == compiler_revision
        assert Package.get_by_string_id('other-libc@1.0').source_urls == []
        read_inputs(ControllersCache(), scan_id)
        assert _package_in_scan(scan_id, 'libc6@2.41').source_urls == [url]
        assert Package.get_by_string_id('libc6@2.41').source_urls == []

    client = app.test_client()
    result = client.get(f'/api/packages?variant_id={variant_id}&format=list').json
    libc = next(package for package in result if package['name'] == 'libc6')
    assert libc['source_revision'] == revision
    assert libc['version_evidence'][-1] == {'source': 'download', 'version': revision, 'identifier': url}
    graph = client.get(f'/api/package-dependencies?variant_id={variant_id}').json
    assert next(pkg for doc in graph['documents'] for pkg in doc['packages']
                if pkg['name'] == 'libc6')['source_revision'] == revision


@pytest.mark.parametrize('multiple_sources', [False, True])
def test_yocto_spdx3_source_build_outputs_preserve_provenance_without_image_or_checksum_inheritance(
        app, tmp_path, multiple_sources):
    revision = 'a' * 40
    urls = [f'git+https://example.org/glibc.git@{revision}']
    if multiple_sources:
        urls.append(f'git+https://example.org/config.git@{"b" * 40}')
    sources = _zephyr_spdx3([
        {'type': 'build_Build', 'spdxId': 'zephyr:build/recipe'},
        *({'type': 'software_Package', 'spdxId': f'zephyr:source/{i}',
           'name': f'source-{i}', 'software_primaryPurpose': 'source', 'software_downloadLocation': url}
          for i, url in enumerate(urls)),
        {'type': 'software_File', 'spdxId': 'zephyr:patch', 'name': 'patch',
         'verifiedUsing': [{'type': 'Hash', 'algorithm': 'sha1', 'hashValue': 'f' * 40}]},
    ])
    # This is a Yocto document, not West: source nodes must remain filtered.
    sources['@graph'] = [item for item in sources['@graph'] if item.get('type') != 'SoftwareAgent']
    build = _zephyr_spdx3([
        {'type': 'build_Build', 'spdxId': 'zephyr:build/image'},
        {'type': 'software_Package', 'spdxId': 'zephyr:binary', 'name': 'libc6',
         'software_packageVersion': '2.41+git', 'software_primaryPurpose': 'install'},
        {'type': 'software_Package', 'spdxId': 'zephyr:image', 'name': 'image', 'software_packageVersion': '1'},
        {'type': 'software_Package', 'spdxId': 'zephyr:direct', 'name': 'direct', 'software_packageVersion': '1',
         'software_downloadLocation': f'git+https://example.org/direct.git@{"c" * 40}'},
        {'type': 'Relationship', 'from': 'https://example.org/zephyr/build/recipe', 'relationshipType': 'hasInput',
         'to': [*(f'zephyr:source/{i}' for i in range(len(urls))), 'zephyr:patch']},
        {'type': 'Relationship', 'from': 'zephyr:build/recipe', 'relationshipType': 'hasOutput', 'to': 'zephyr:binary'},
        {'type': 'Relationship', 'from': 'zephyr:build/image', 'relationshipType': 'hasInput',
         'to': ['zephyr:binary', 'zephyr:direct']},
        {'type': 'Relationship', 'from': 'zephyr:build/image', 'relationshipType': 'hasOutput', 'to': ['zephyr:image']},
        {'type': 'Relationship', 'from': 'zephyr:unknown-build', 'relationshipType': 'hasInput',
         'to': ['zephyr:source/0']},
        {'type': 'Relationship', 'from': 'zephyr:unknown-build', 'relationshipType': 'hasOutput',
         'to': ['zephyr:image']},
    ])
    with app.app_context():
        project = Project.create('yocto-spdx3-source')
        variant = Variant.create('default', project.id)
        scan = Scan.create('SBOM', variant.id)
        scan_id = scan.id
        for name, document in [('build', build), ('sources', sources)]:
            path = tmp_path / f'{name}.jsonld'
            path.write_text(json.dumps(document))
            SBOMDocument.create(str(path), path.name, scan.id, format='spdx')
        read_inputs(ControllersCache(), scan_id)
        db.session.remove()
        assert len(Package.get_all()) == 3
        binary = _package_in_scan(scan_id, 'libc6@2.41')
        assert binary.source_urls == sorted(urls)
        assert binary.version_info['release_version'] == '2.41'
        assert binary.version_info['source_revision'] == (None if multiple_sources else revision)
        assert binary.version_info['revision_conflict'] == multiple_sources
        assert _package_in_scan(scan_id, 'direct@1').version_info['source_revision'] == 'c' * 40
        assert Package.get_by_string_id('image@1').source_urls == []
        assert db.session.query(PackageDependency).count() == 0
        read_inputs(ControllersCache(), scan_id)
        assert _package_in_scan(scan_id, 'libc6@2.41').source_urls == sorted(urls)


@pytest.mark.parametrize('format_name', ['spdx2', 'spdx3'])
@pytest.mark.parametrize('ignore_parsing_errors', ['false', 'true'])
def test_git_source_evidence_is_scoped_to_active_documents_in_apis_and_exports(
        app, tmp_path, monkeypatch, format_name, ignore_parsing_errors):
    from src.helpers.export_scope import compute_export_scope
    from src.views.spdx import SPDX
    from src.views.spdx3 import SPDX3

    monkeypatch.setenv('IGNORE_PARSING_ERRORS', ignore_parsing_errors)
    urls = [f'git+https://example.org/repo-{i}@{str(i) * 40}' for i in (1, 2, 3)]
    variants = {}

    def ingest(project_name, url):
        project = Project.get_by_name(project_name) or Project.create(project_name)
        variant = Variant.get_by_name_and_project('default', project.id) or Variant.create('default', project.id)
        variants[project_name] = variant.id
        scan = Scan.create('SBOM', variant.id)
        if format_name == 'spdx3':
            pkg = {'type': 'software_Package', 'spdxId': 'pkg:lib', 'name': 'lib', 'software_packageVersion': '1.0'}
            if url:
                pkg['software_downloadLocation'] = url
            document = {'@graph': [{'type': 'CreationInfo', 'specVersion': '3.0.1'}, pkg]}
        else:
            document = _yocto_spdx2(project_name, packages=(('SPDXRef-lib', 'lib'),))
            document['packages'][0]['downloadLocation'] = url or 'NOASSERTION'
        path = tmp_path / f'{project_name}-{scan.id}.json'
        path.write_text(json.dumps(document))
        SBOMDocument.create(str(path), path.name, scan.id, format='spdx')
        read_inputs(ControllersCache(), scan.id)
        return project.id, scan.id

    project_a, old_scan = ingest('A', urls[0])
    project_b, scan_b = ingest('B', None)
    _, _ = ingest('C', urls[1])
    _, new_scan = ingest('A', urls[2])
    db.session.remove()
    shared = Package.get_by_string_id('lib@1.0')
    assert len(Package.get_all()) == 1
    assert shared.source_urls == []
    assert _package_in_scan(old_scan, 'lib@1.0').source_urls == [urls[0]]
    assert _package_in_scan(new_scan, 'lib@1.0').source_urls == [urls[2]]
    client = app.test_client()

    for selection, expected in [
        (f'variant_id={variants["A"]}', [urls[2]]),
        (f'variant_id={variants["B"]}', []),
        (f'project_id={project_a}', [urls[2]]),
        (f'project_id={project_b}', []),
        (f'variant_ids={variants["A"]},{variants["B"]}', [urls[2]]),
        (f'variant_ids={variants["A"]},{variants["C"]}&operation=intersection', [urls[1], urls[2]]),
        (f'variant_id={variants["A"]}&compare_variant_id={variants["B"]}&operation=intersection', [urls[2]]),
    ]:
        row = client.get(f'/api/packages?{selection}').json[0]
        assert row['source_urls'] == expected
        assert row['source_revision'] == (expected[0].split('@')[-1] if len(expected) == 1 else None)
        assert row['revision_conflict'] == (len(expected) > 1)
        graphs = client.get(f'/api/package-dependencies?{selection}').json['documents']
        graph_urls = sorted({evidence['identifier'] for graph in graphs for pkg in graph['packages']
                             for evidence in pkg['version_evidence'] if evidence['source'] == 'download'})
        assert graph_urls == expected

    for selector, expected in [
        ({'variant_id': variants['A']}, [urls[2]]),
        ({'variant_id': variants['B']}, []),
        ({'project_id': project_a}, [urls[2]]),
        ({'variant_ids': [variants['A'], variants['C']]}, [urls[1], urls[2]]),
    ]:
        scope = compute_export_scope(**selector)
        assert old_scan not in {doc.scan_id for doc in SBOMDocument.get_all()
                               if doc.id in scope.active_sbom_document_ids}
        for preload in (False, True):
            controllers = ControllersCache(scope=scope)
            if preload:
                controllers.packages._preload_cache()
            else:
                assert controllers.packages.get('lib@1.0') is not None
            snapshot = controllers.packages.to_dict()['lib@1.0']
            assert snapshot['source_urls'] == expected
            assert shared.source_urls == []
            spdx2 = json.loads(SPDX(controllers).output_as_json())
            assert sorted(pkg['downloadLocation'] for pkg in spdx2.get('packages', [])
                          if pkg.get('primaryPackagePurpose') == 'SOURCE') == expected
            spdx3 = json.loads(SPDX3(controllers).output_as_json())
            assert sorted(pkg['software_downloadLocation'] for pkg in spdx3['@graph']
                          if pkg.get('software_primaryPurpose') == 'source') == expected

    global_controllers = ControllersCache()
    global_controllers.packages._preload_cache()
    assert global_controllers.packages.get('lib@1.0').source_urls == [urls[1], urls[2]]
    assert client.get('/api/packages').json[0]['source_urls'] == [urls[1], urls[2]]
    for project_name, expected in [('A', [urls[2]]), ('B', [])]:
        for export_format, filename in [('spdx2', 'sbom_spdx_v2_3.spdx.json'),
                                        ('spdx3', 'sbom_spdx_v3_0.spdx.json')]:
            output_dir = tmp_path / f'export-{project_name}-{export_format}'
            response = app.test_cli_runner().invoke(args=[
                'export', '--format', export_format, '--project', project_name,
                '--variant', 'default', '--output-dir', str(output_dir),
            ])
            assert response.exit_code == 0, response.output
            with open(output_dir / filename) as output:
                exported = json.load(output)
            locations = sorted(
                pkg['downloadLocation'] for pkg in exported.get('packages', [])
                if pkg.get('primaryPackagePurpose') == 'SOURCE'
            ) if export_format == 'spdx2' else sorted(
                pkg['software_downloadLocation'] for pkg in exported['@graph']
                if pkg.get('software_primaryPurpose') == 'source'
            )
            assert locations == expected

    # Reimporting one document replaces, rather than accumulates, its evidence.
    doc_b = SBOMDocument.get_by_scan(scan_b)[0]
    path_b = doc_b.path
    with open(path_b) as source:
        data = json.load(source)
    pkg = data['packages'][0] if format_name == 'spdx2' else data['@graph'][1]
    field = 'downloadLocation' if format_name == 'spdx2' else 'software_downloadLocation'
    for value in (urls[1], 'NOASSERTION', urls[1]):
        pkg[field] = value
        with open(path_b, 'w') as output:
            json.dump(data, output)
        read_inputs(ControllersCache(), scan_b)
        db.session.remove()
        row_b = client.get(f'/api/packages?variant_id={variants["B"]}').json[0]
        assert row_b['source_urls'] == ([value] if value != 'NOASSERTION' else [])
        assert client.get(f'/api/packages?variant_id={variants["A"]}').json[0]['source_urls'] == [urls[2]]

    # Empty documents must clear old link evidence; cleaned-up inputs must retain it.
    if format_name == 'spdx2':
        data['packages'] = []
    else:
        data['@graph'] = data['@graph'][:1]
    with open(path_b, 'w') as output:
        json.dump(data, output)
    read_inputs(ControllersCache(), scan_b)
    db.session.remove()
    assert _package_in_scan(scan_b, 'lib@1.0').source_urls == []
    Path(SBOMDocument.get_by_scan(new_scan)[0].path).unlink()
    read_inputs(ControllersCache(), new_scan)
    db.session.remove()
    assert _package_in_scan(new_scan, 'lib@1.0').source_urls == [urls[2]]


def test_same_package_in_companion_documents_keeps_each_documents_source_evidence(app, tmp_path):
    project = Project.create('document-evidence')
    variant = Variant.create('default', project.id)
    variant_id = variant.id
    scan = Scan.create('SBOM', variant.id)
    scan_id = scan.id
    urls = [f'git+https://example.org/repo-{i}@{str(i) * 40}' for i in (1, 2)]
    for i, url in enumerate([*urls, None]):
        pkg = {'type': 'software_Package', 'spdxId': f'pkg:lib-{i}', 'name': 'lib', 'software_packageVersion': '1.0'}
        if url:
            pkg['software_downloadLocation'] = url
        path = tmp_path / f'{i}.jsonld'
        path.write_text(json.dumps({'@graph': [{'type': 'CreationInfo', 'specVersion': '3.0.1'}, pkg]}))
        SBOMDocument.create(str(path), path.name, scan.id, format='spdx')
    read_inputs(ControllersCache(), scan_id)
    db.session.remove()
    client = app.test_client()
    row = client.get(f'/api/packages?variant_id={variant_id}').json[0]
    assert row['source_urls'] == urls
    assert row['revision_conflict']
    graphs = client.get(f'/api/package-dependencies?variant_id={variant_id}').json['documents']
    assert [doc['packages'][0]['source_revision'] for doc in graphs] == ['1' * 40, '2' * 40, None]
    assert not any(doc['packages'][0]['revision_conflict'] for doc in graphs)


@pytest.mark.parametrize('format_name', ['spdx2', 'spdx3', 'cdx'])
@pytest.mark.parametrize('ignore_parsing_errors', ['false', 'true'])
def test_identifier_evidence_is_document_scoped_and_replaced_on_reimport(
        app, tmp_path, monkeypatch, format_name, ignore_parsing_errors):
    from src.helpers.export_scope import compute_export_scope
    from src.views.spdx import SPDX
    from src.views.spdx3 import SPDX3

    monkeypatch.setenv('IGNORE_PARSING_ERRORS', ignore_parsing_errors)
    identifiers = {
        name: ([f'pkg:generic/vendor/lib@{index}.0', f'pkg:generic/vendor/lib@{str(index) * 40}'],
               [f'cpe:2.3:a:vendor:lib:{index}.0:*:*:*:*:*:*:*'])
        for index, name in enumerate(['old-A', 'C', 'A'], 1)
    }
    variants = {}

    def document(purls, cpes):
        if format_name == 'spdx2':
            data = _yocto_spdx2('identifiers', packages=(('SPDXRef-lib', 'lib'),))
            data['packages'][0].pop('versionInfo')
            data['packages'][0]['externalRefs'] = [
                {'referenceCategory': 'PACKAGE-MANAGER', 'referenceType': 'purl', 'referenceLocator': purl}
                for purl in purls
            ] + [
                {'referenceCategory': 'SECURITY', 'referenceType': 'cpe23Type', 'referenceLocator': cpe}
                for cpe in cpes
            ]
            return data
        if format_name == 'cdx':
            return {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1, 'components': [
                {'type': 'library', 'name': 'lib', **({'purl': purls[0]} if purls else {}),
                 **({'cpe': cpes[0]} if cpes else {})},
            ]}
        return {'@graph': [
            {'type': 'CreationInfo', 'specVersion': '3.0.1'},
            {'type': 'software_Package', 'spdxId': 'pkg:lib', 'name': 'lib', 'externalIdentifier': [
                {'externalIdentifierType': 'purl', 'identifier': purl} for purl in purls
            ] + [{'externalIdentifierType': 'cpe23', 'identifier': cpe} for cpe in cpes]},
        ]}

    def ingest(name, key=None):
        project = Project.get_by_name(name) or Project.create(name)
        variant = Variant.get_by_name_and_project('default', project.id) or Variant.create('default', project.id)
        variants[name] = variant.id
        scan = Scan.create('SBOM', variant.id)
        purls, cpes = identifiers[key or name] if key or name in identifiers else ([], [])
        path = tmp_path / f'{scan.id}.json'
        path.write_text(json.dumps(document(purls, cpes)))
        link = SBOMDocument.create(str(path), path.name, scan.id, format='cdx' if format_name == 'cdx' else 'spdx')
        read_inputs(ControllersCache(), scan.id)
        return project.id, scan.id, link.id, path

    _, old_scan, _, _ = ingest('A', 'old-A')
    project_b, scan_b, _, path_b = ingest('B')
    ingest('C')
    project_a, scan_a, _, _ = ingest('A')
    db.session.remove()
    shared = Package.get_by_string_id('lib@')
    assert len(Package.get_all()) == 1
    assert all(purl in shared.purl for purl in identifiers['A'][0][:1])
    assert identifiers['old-A'][0][0] in shared.purl
    client = app.test_client()
    for selection, release, revision in [
        (f'variant_id={variants["A"]}', '3.0', '3' * 40),
        (f'project_id={project_a}', '3.0', '3' * 40),
        (f'variant_id={variants["B"]}', None, None),
        (f'project_id={project_b}', None, None),
    ]:
        row = client.get(f'/api/packages?{selection}').json[0]
        assert row['release_version'] == release
        assert row['source_revision'] == (revision if format_name != 'cdx' else None)
        assert not row['version_conflict'] and not row['revision_conflict']
        assert not set(identifiers['old-A'][0] + identifiers['old-A'][1]) & set(row['purl'] + row['cpe'])
        if release is None:
            assert not set(sum((p + c for p, c in identifiers.values()), [])) & set(row['purl'] + row['cpe'])
        graph = client.get(f'/api/package-dependencies?{selection}').json['documents'][0]['packages'][0]
        assert graph['release_version'] == row['release_version']
        assert graph['source_revision'] == row['source_revision']
        assert graph['version_evidence'] == row['version_evidence']
    combined = client.get(f'/api/packages?variant_ids={variants["A"]},{variants["C"]}').json[0]
    assert combined['version_conflict']
    assert combined['revision_conflict'] == (format_name != 'cdx')
    for name, scan_id in [('A', scan_a), ('B', scan_b)]:
        for preload in (False, True):
            controllers = ControllersCache(scope=compute_export_scope(variant_id=variants[name]))
            if preload:
                controllers.packages._preload_cache()
            snapshot = controllers.packages.get('lib@')
            assert snapshot.version_info['release_version'] == ('3.0' if name == 'A' else None)
            for output in [json.loads(SPDX(controllers).output_as_json()), json.loads(SPDX3(controllers).output_as_json())]:
                serialized = json.dumps(output)
                for key in ('old-A', 'C'):
                    assert all(identifier not in serialized for identifier in sum(identifiers[key], []))
            assert SBOMPackage.evidence_for_documents(
                {doc.id for doc in SBOMDocument.get_by_scan(scan_id)}
            )[shared.id]['purl'] == snapshot.purl
    assert old_scan != scan_a
    for purls, cpes in [identifiers['C'], ([], [])]:
        path_b.write_text(json.dumps(document(purls, cpes)))
        read_inputs(ControllersCache(), scan_b)
        db.session.remove()
        row = client.get(f'/api/packages?variant_id={variants["B"]}').json[0]
        assert row['release_version'] == ('2.0' if purls else None)
        assert row['source_revision'] == ('2' * 40 if purls and format_name != 'cdx' else None)
        assert client.get(f'/api/packages?variant_id={variants["A"]}').json[0]['release_version'] == '3.0'


@pytest.mark.parametrize('identifier_type', ['purl', 'cpe23'])
def test_companion_identifier_evidence_is_document_local_not_last_writer_wins(app, tmp_path, identifier_type):
    project = Project.create('companion-identifiers')
    variant = Variant.create('default', project.id)
    variant_id = variant.id
    scan = Scan.create('SBOM', variant.id)
    scan_id = scan.id
    for index in range(3):
        revision = str(index + 1) * 40
        identifier = (f'pkg:generic/lib@{revision}' if identifier_type == 'purl'
                      else f'cpe:2.3:a:vendor:lib:{revision}:*:*:*:*:*:*:*')
        document = {'@graph': [
            {'type': 'CreationInfo', 'specVersion': '3.0.1'},
            {'type': 'software_Package', 'spdxId': f'pkg:lib-{index}', 'name': 'lib',
             'software_packageVersion': '1.0', 'externalIdentifier': [
                 {'externalIdentifierType': identifier_type, 'identifier': identifier},
             ] if index < 2 else []},
        ]}
        path = tmp_path / f'{index}.jsonld'
        path.write_text(json.dumps(document))
        SBOMDocument.create(str(path), path.name, scan_id, format='spdx')
    read_inputs(ControllersCache(), scan_id)
    db.session.remove()
    client = app.test_client()
    row = client.get(f'/api/packages?variant_id={variant_id}').json[0]
    assert row['source_revision'] is None
    assert row['revision_conflict']
    graphs = client.get(f'/api/package-dependencies?variant_id={variant_id}').json['documents']
    assert [graph['packages'][0]['source_revision'] for graph in graphs] == ['1' * 40, '2' * 40, None]
    assert all(not graph['packages'][0]['revision_conflict'] for graph in graphs)
    assert all(graph['packages'][0]['release_version'] == '1.0' for graph in graphs)


@pytest.mark.parametrize('ignore_parsing_errors', ['false', 'true'])
@pytest.mark.parametrize('source_comment', [None, 'VulnScout: synthetic Git source provenance'])
def test_unmarked_git_source_with_only_generated_from_keeps_its_document_association(
        app, tmp_path, monkeypatch, ignore_parsing_errors, source_comment):
    from src.views.spdx import SPDX

    monkeypatch.setenv('IGNORE_PARSING_ERRORS', ignore_parsing_errors)
    exporter = SPDX(ControllersCache())
    exporter.packagesCtrl.add(Package('app', '1.0'))
    document = json.loads(exporter.output_as_json())
    url = f'git+https://example.org/lib@{"a" * 40}'
    document['packages'].append({
        'SPDXID': 'SPDXRef-real-source', 'name': 'real-source', 'filesAnalyzed': False,
        'primaryPackagePurpose': 'SOURCE', 'downloadLocation': url,
        **({'comment': source_comment} if source_comment else {}),
    })
    document['relationships'].append({
        'spdxElementId': document['packages'][0]['SPDXID'], 'relationshipType': 'GENERATED_FROM',
        'relatedSpdxElement': 'SPDXRef-real-source',
    })
    variant_id, scan_id = _scan(app, tmp_path, 'real-source', document)
    document_id = SBOMDocument.get_by_scan(scan_id)[0].id
    source = Package.get_by_string_id('real-source@')
    assert source is not None
    assert SBOMPackage.get(document_id, source.id) is not None
    rows = app.test_client().get(f'/api/packages?variant_id={variant_id}').json
    assert {row['id'] for row in rows} == {'app@1.0', 'real-source@'}
    assert all(row['source_urls'] == [url] for row in rows)
    graph = app.test_client().get(f'/api/package-dependencies?variant_id={variant_id}').json['documents'][0]
    assert {row['id'] for row in graph['packages']} == {'app@1.0', 'real-source@'}


@pytest.mark.parametrize('ignore_parsing_errors', ['false', 'true'])
def test_scoped_spdx2_export_import_cycles_preserve_installed_package_set_and_provenance(
        app, tmp_path, monkeypatch, ignore_parsing_errors):
    from src.helpers.export_scope import compute_export_scope
    from src.views.spdx import SPDX

    monkeypatch.setenv('IGNORE_PARSING_ERRORS', ignore_parsing_errors)
    project = Project.create('roundtrip-installed')
    variant = Variant.create('default', project.id)
    variant_id = variant.id
    scan = Scan.create('SBOM', variant_id)
    urls = [f'git+https://example.org/source-{i}@{str(i) * 40}' for i in (1, 2)]
    controllers = ControllersCache()
    document = SBOMDocument.create('initial.json', 'initial', scan.id)
    controllers.packages.current_sbom_document = document
    packages = [
        Package('libc6', '2.41', cpe=['cpe:2.3:*:*:glibc:2.41:*:*:*:*:*:*:*'],
                purl=['pkg:generic/glibc@2.41'], source_urls=urls),
        Package('other', '1.0'),
    ]
    for package in packages:
        package.generate_generic_cpe()
        package.generate_generic_purl()
        controllers.packages.add(package)
    controllers.packages.flush_spdx_sources()
    db.session.commit()
    expected_evidence = SBOMPackage.evidence_for_documents({document.id})
    for index in range(3):
        db.session.remove()
        controllers = ControllersCache(scope=compute_export_scope(variant_id=variant_id))
        controllers.packages._preload_cache()
        exported = json.loads(SPDX(controllers).output_as_json(with_cpe=True))
        assert len(exported['packages']) == 4
        path = tmp_path / f'cycle-{index}.spdx.json'
        path.write_text(json.dumps(exported))
        scan = Scan.create('SBOM', variant_id)
        scan_id = scan.id
        SBOMDocument.create(str(path), path.name, scan.id, format='spdx')
        read_inputs(ControllersCache(), scan.id)
        db.session.remove()
        assert SBOMPackage.evidence_for_documents(
            {doc.id for doc in SBOMDocument.get_by_scan(scan_id)}
        ) == expected_evidence
        rows = app.test_client().get(f'/api/packages?variant_id={variant_id}').json
        assert {row['id'] for row in rows} == {'libc6@2.41', 'other@1.0'}
        assert next(row for row in rows if row['name'] == 'libc6')['source_urls'] == urls
        assert {pkg.string_id for pkg in Package.get_all()} == {'libc6@2.41', 'other@1.0'}


@pytest.mark.parametrize('ignore_parsing_errors', ['false', 'true'])
def test_yocto_spdx2_dependencies_resolve_across_documents_of_one_scan(
        app, tmp_path, monkeypatch, ignore_parsing_errors):
    monkeypatch.setenv('IGNORE_PARSING_ERRORS', ignore_parsing_errors)
    with app.app_context():
        project = Project.create('yocto')
        project_id = project.id
        variants = [Variant.create(name, project.id) for name in ('first', 'second')]
        first_variant_id = variants[0].id
        for variant in variants:
            scan = Scan.create('SBOM', variant.id)
            for name, document in _yocto_archive().items():
                path = tmp_path / f'{variant.name}-{name}.spdx.json'
                path.write_text(json.dumps(document))
                SBOMDocument.create(str(path), path.name, scan.id, format='spdx')
        read_inputs(ControllersCache())

        rows = db.session.execute(
            db.select(SBOMDocument.source_name, PackageDependency.package_id, PackageDependency.dependency_id)
            .join(SBOMDocument, SBOMDocument.id == PackageDependency.sbom_document_id)
        ).all()
        names = {package.id: package.name for package in Package.get_all()}
        assert sorted((source, names[package], names[dependency]) for source, package, dependency in rows) == [
            ('first-recipe-app.spdx.json', 'app', 'lib'), ('first-recipe-app.spdx.json', 'app', 'util'),
            ('second-recipe-app.spdx.json', 'app', 'lib'), ('second-recipe-app.spdx.json', 'app', 'util'),
        ]

    client = app.test_client()
    assert client.get(f'/api/package-dependencies?variant_id={first_variant_id}&counts=1').json['counts'] == {
        'app@1.0': {'in': 2, 'out': 0}, 'lib@1.0': {'in': 0, 'out': 1}, 'util@1.0': {'in': 0, 'out': 1},
    }
    documents = client.get(f'/api/package-dependencies?project_id={project_id}').json['documents']
    assert [(document['variant_name'], document['source_name'], len(document['edges']))
            for document in documents if document['edges']] == [
        ('first', 'first-recipe-app.spdx.json', 2), ('second', 'second-recipe-app.spdx.json', 2),
    ]

    recipe = _yocto_archive()['recipe-app']
    recipe['relationships'] = []
    (tmp_path / 'first-recipe-app.spdx.json').write_text(json.dumps(recipe))
    with app.app_context():
        read_inputs(ControllersCache())
        assert sorted((source, names[package], names[dependency]) for source, package, dependency in db.session.execute(
            db.select(SBOMDocument.source_name, PackageDependency.package_id, PackageDependency.dependency_id)
            .join(SBOMDocument, SBOMDocument.id == PackageDependency.sbom_document_id)
        )) == [
            ('first-recipe-app.spdx.json', 'app', 'util'),
            ('second-recipe-app.spdx.json', 'app', 'lib'), ('second-recipe-app.spdx.json', 'app', 'util'),
        ]


def _scan_edges(scan_id):
    names = {package.id: package.string_id for package in Package.get_all()}
    return sorted((names[package], names[dependency]) for package, dependency in db.session.execute(
        db.select(PackageDependency.package_id, PackageDependency.dependency_id)
        .join(SBOMDocument, SBOMDocument.id == PackageDependency.sbom_document_id)
        .where(SBOMDocument.scan_id == scan_id)
    ))


def _exported_spdx2_edges(document):
    names = {package['SPDXID']: package['name'] for package in document['packages']}
    return sorted((names[relation['spdxElementId']], names[relation['relatedSpdxElement']])
                  for relation in document['relationships'] if relation['relationshipType'] == 'DEPENDS_ON')


def _exported_spdx3_edges(document):
    names = {item['spdxId']: item['name'] for item in document['@graph'] if item.get('type') == 'software_Package'}
    return sorted((names[relation['from']], names[target]) for relation in document['@graph']
                  if relation.get('relationshipType') == 'dependsOn' for target in relation['to'])


@pytest.mark.parametrize('format_name', ['spdx2', 'spdx3'])
@pytest.mark.parametrize('ignore_parsing_errors', ['false', 'true'])
def test_scoped_spdx_export_import_cycles_preserve_cross_document_dependencies(
        app, tmp_path, monkeypatch, format_name, ignore_parsing_errors):
    from xml.etree import ElementTree
    from src.helpers.export_scope import compute_export_scope
    from src.views.spdx import SPDX
    from src.views.spdx3 import SPDX3

    monkeypatch.setenv('IGNORE_PARSING_ERRORS', ignore_parsing_errors)
    project = Project.create('dependency-export')
    variant_id = Variant.create('default', project.id).id
    scan_id = Scan.create('SBOM', variant_id).id
    for name, document in _yocto_archive().items():
        path = tmp_path / f'{name}.spdx.json'
        path.write_text(json.dumps(document))
        SBOMDocument.create(str(path), path.name, scan_id, format='spdx')
    read_inputs(ControllersCache(), scan_id)
    # The same packages depend on each other in another variant only; that edge must not leak.
    other_variant = Variant.create('other', project.id)
    other_scan_id = Scan.create('SBOM', other_variant.id).id
    other = _yocto_spdx2('other', packages=(('SPDXRef-lib', 'lib'), ('SPDXRef-util', 'util')),
                         relationships=(('SPDXRef-util', 'DEPENDS_ON', 'SPDXRef-lib'),))
    path = tmp_path / 'other.spdx.json'
    path.write_text(json.dumps(other))
    SBOMDocument.create(str(path), path.name, other_scan_id, format='spdx')
    read_inputs(ControllersCache(), other_scan_id)
    expected = [('app@1.0', 'lib@1.0'), ('app@1.0', 'util@1.0')]
    assert _scan_edges(scan_id) == expected
    assert _scan_edges(other_scan_id) == [('util@1.0', 'lib@1.0')]

    for index in range(2):
        db.session.remove()
        controllers = ControllersCache(scope=compute_export_scope(variant_id=variant_id))
        controllers.packages._preload_cache()
        if format_name == 'spdx2':
            exporter = SPDX(controllers)
            exported = json.loads(exporter.output_as_json())
            assert _exported_spdx2_edges(exported) == [('app', 'lib'), ('app', 'util')]
            xml = ElementTree.fromstring(exporter.output_as_xml())
            assert [relation.findtext('relationshipType') for relation in xml.findall('relationships')].count(
                'DEPENDS_ON') == 2
        else:
            exported = json.loads(SPDX3(controllers).output_as_json())
            assert _exported_spdx3_edges(exported) == [('app', 'lib'), ('app', 'util')]
            assert len([item for item in exported['@graph'] if item.get('relationshipType') == 'dependsOn']) == 1
        path = tmp_path / f'cycle-{index}.spdx.json'
        path.write_text(json.dumps(exported))
        scan_id = Scan.create('SBOM', variant_id).id
        SBOMDocument.create(str(path), path.name, scan_id, format='spdx')
        read_inputs(ControllersCache(), scan_id)
        assert _scan_edges(scan_id) == expected

    graph = app.test_client().get(f'/api/package-dependencies?variant_id={variant_id}').json['documents']
    assert [(edge['package_id'], edge['dependency_id']) for document in graph for edge in document['edges']] == expected

    global_controllers = ControllersCache()
    global_controllers.packages._preload_cache()
    global_edges = [('app', 'lib'), ('app', 'util'), ('util', 'lib')]
    assert _exported_spdx2_edges(json.loads(SPDX(global_controllers).output_as_json())) == global_edges
    assert _exported_spdx3_edges(json.loads(SPDX3(global_controllers).output_as_json())) == global_edges
    assert SPDX(ControllersCache()).packagesCtrl.dependency_edges() == set()


def test_spdx3_ingestion_and_scoped_api(app, tmp_path):
    variant, scan_id = _scan(app, tmp_path, 'one', _spdx3())
    client = app.test_client()
    response = client.get(f'/api/package-dependencies?variant_id={variant}')
    assert response.status_code == 200
    document = response.json['documents'][0]
    assert (document['variant_id'], document['variant_name']) == (str(variant), 'one')
    names = {package['id']: package['name'] for package in document['packages']}
    assert set(names) == {'app@1.0', 'lib@1.0', 'util@1.0'}
    assert set(names.values()) == {'app', 'lib', 'util'}
    assert {(names[edge['package_id']], names[edge['dependency_id']]) for edge in document['edges']} == {
        ('app', 'lib'), ('app', 'util'), ('lib', 'util'),
    }
    counts = client.get(f'/api/package-dependencies?variant_id={variant}&counts=1').json['counts']
    assert counts == {
        'app@1.0': {'in': 2, 'out': 0},
        'lib@1.0': {'in': 1, 'out': 1},
        'util@1.0': {'in': 0, 'out': 2},
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


@pytest.mark.parametrize('format_name', ['spdx3', 'spdx2', 'cdx'])
def test_document_references_do_not_resolve_through_previous_document(app, tmp_path, format_name):
    with app.app_context():
        project = Project.create(f'{format_name}-project')
        variant = Variant.create('default', project.id)
        scan = Scan.create('SBOM', variant.id)

        def document(source_ref, lib_ref, target_refs):
            if format_name == 'spdx3':
                return {'@graph': [
                    {'type': 'CreationInfo', 'specVersion': '3.0.1'},
                    *({'type': 'software_Package', 'spdxId': ref, 'name': name,
                        'software_packageVersion': '1.0'}
                      for ref, name in ((source_ref, 'app'), (lib_ref, 'lib'))),
                    {'type': 'Relationship', 'relationshipType': 'dependsOn',
                     'from': source_ref, 'to': target_refs},
                ]}
            if format_name == 'spdx2':
                return {
                    'spdxVersion': 'SPDX-2.3', 'SPDXID': 'SPDXRef-DOCUMENT',
                    'creationInfo': {'creators': ['Tool: test'], 'created': '2024-01-01T00:00:00Z'},
                    'name': 'test', 'dataLicense': 'CC0-1.0',
                    'documentNamespace': f'https://example.org/{source_ref}',
                    'packages': [
                        {'SPDXID': ref, 'name': name, 'versionInfo': '1.0',
                         'downloadLocation': 'NOASSERTION'}
                        for ref, name in ((source_ref, 'app'), (lib_ref, 'lib'))
                    ],
                    'relationships': [
                        {'spdxElementId': source_ref, 'relationshipType': 'DEPENDS_ON',
                         'relatedSpdxElement': target} for target in target_refs
                    ],
                }
            return {
                'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'version': 1,
                'components': [
                    {'type': 'library', 'bom-ref': ref, 'name': name, 'version': '1.0'}
                    for ref, name in ((source_ref, 'app'), (lib_ref, 'lib'))
                ],
                'dependencies': [{'ref': source_ref, 'dependsOn': target_refs}],
            }

        for name, source, lib, targets in (
            ('a', 'app-a', 'lib-a', ['lib-a']),
            ('b', 'app-b', 'lib-b', ['lib-a']),
        ):
            path = tmp_path / f'{name}.json'
            path.write_text(json.dumps(document(source, lib, targets)))
            SBOMDocument.create(str(path), path.name, scan.id,
                                format='cdx' if format_name == 'cdx' else 'spdx')

        read_inputs(ControllersCache(), scan.id)
        documents = SBOMDocument.get_by_scan(scan.id)
        assert [document.source_name for document in documents] == ['a.json', 'b.json']
        assert [db.session.query(PackageDependency).filter_by(sbom_document_id=doc.id).count()
            for doc in documents] == [1, 0]


def test_cdx_vulnerabilities_still_resolve_components_from_previous_document(app, tmp_path):
    with app.app_context():
        project = Project.create('vex-project')
        variant = Variant.create('default', project.id)
        scan = Scan.create('SBOM', variant.id)
        documents = {
            'sbom': {'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'version': 1,
                     'components': [{'type': 'library', 'bom-ref': 'app-ref', 'name': 'app', 'version': '1.0'}]},
            'vex': {'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'version': 1,
                    'vulnerabilities': [{'id': 'CVE-2024-0001', 'affects': [{'ref': 'app-ref'}]}]},
        }
        for name, document in documents.items():
            path = tmp_path / f'{name}.json'
            path.write_text(json.dumps(document))
            SBOMDocument.create(str(path), path.name, scan.id, format='cdx')

        read_inputs(ControllersCache(), scan.id)
        findings = db.session.execute(
            db.select(Finding.vulnerability_id).join(Package, Package.id == Finding.package_id)
            .where(Package.name == 'app')
        ).scalars().all()
        assert findings == ['CVE-2024-0001']


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


def test_deleting_package_removes_incoming_and_outgoing_edges(app, tmp_path):
    variant_id, _ = _scan(app, tmp_path, 'package', _spdx3())
    with app.app_context():
        assert ControllersCache().packages.remove('lib@1.0')
        names = {package.id: package.name for package in Package.get_all()}
        assert [(names[edge.package_id], names[edge.dependency_id])
                for edge in db.session.query(PackageDependency)] == [('app', 'util')]

    client = app.test_client()
    counts = client.get(f'/api/package-dependencies?variant_id={variant_id}&counts=1')
    assert counts.status_code == 200
    assert counts.json['counts'] == {'app@1.0': {'in': 1, 'out': 0}, 'util@1.0': {'in': 0, 'out': 1}}
    graph = client.get(f'/api/package-dependencies?variant_id={variant_id}')
    assert graph.status_code == 200
    assert graph.json['documents'][0]['edges'] == [{'package_id': 'app@1.0', 'dependency_id': 'util@1.0'}]


def test_documents_without_recorded_dependencies_are_not_reported_as_zero(app, tmp_path):
    variant_id, scan_id = _scan(app, tmp_path, 'recorded', _spdx3())
    with app.app_context():
        assert [document.dependencies_recorded for document in SBOMDocument.get_by_scan(scan_id)] == [True]
        # An SBOM merged before dependency support: its source file was removed after import.
        legacy_path = tmp_path / 'legacy.json'
        legacy = SBOMDocument.create(str(legacy_path), legacy_path.name, scan_id, format='spdx')
        legacy_id = legacy.id
        legacy_package = Package.create('legacy', '2.0')
        db.session.add(SBOMPackage(sbom_document_id=legacy.id, package_id=legacy_package.id))
        db.session.commit()
        read_inputs(ControllersCache(), scan_id)
        assert db.session.get(SBOMDocument, legacy_id).dependencies_recorded is False

    client = app.test_client()
    counts = client.get(f'/api/package-dependencies?variant_id={variant_id}&counts=1').json
    assert counts['unrecorded'] == ['legacy@2.0']
    assert 'legacy@2.0' not in counts['counts']
    documents = client.get(f'/api/package-dependencies?variant_id={variant_id}').json['documents']
    assert {document['source_name']: document['dependencies_recorded'] for document in documents} == {
        'legacy.json': False, 'recorded.json': True,
    }

    # Importing the source file again records its relationships.
    legacy_path.write_text(json.dumps({'@graph': [
        {'type': 'CreationInfo', 'specVersion': '3.0.1'},
        {'type': 'software_Package', 'spdxId': 'pkg:legacy', 'name': 'legacy', 'software_packageVersion': '2.0'},
    ]}))
    with app.app_context():
        read_inputs(ControllersCache(), scan_id)
    assert client.get(f'/api/package-dependencies?variant_id={variant_id}&counts=1').json['unrecorded'] == []
    assert client.get('/api/package-dependencies?variant_id=00000000-0000-0000-0000-000000000000&counts=1').json == {
        'counts': {}, 'unrecorded': [],
    }


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
        counts = client.get(f'/api/package-dependencies?{query}&counts=1').json['counts']
        assert counts == ({'core@1.0': {'in': 1, 'out': 0}, 'other@1.0': {'in': 0, 'out': 1}}
                          if operation == 'difference' else {})

    intersection = client.get(
        f'/api/package-dependencies?variant_ids={base_id},{compare_id}&operation=intersection'
    )
    assert intersection.status_code == 200
    assert {package['name'] for doc in intersection.json['documents']
            for package in doc['packages']} == {'app'}

    union = client.get(f'/api/package-dependencies?variant_ids={base_id}&compare_variant_id={compare_id}')
    assert union.status_code == 200
    assert {package['name'] for doc in union.json['documents']
            for package in doc['packages']} == {'app', 'lib', 'util'}


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


def _cdx_bundled(root_type='application', root_edges=True):
    """CycloneDX 1.4 BOM shaped like the bom-examples juice-shop npm "bare" output (bundled nested packages)."""
    return {
        'bomFormat': 'CycloneDX', 'specVersion': '1.4', 'version': 1,
        'metadata': {'component': {'type': root_type, 'bom-ref': 'shop', 'name': 'shop', 'version': '11.1.2'}},
        'components': [
            {'type': 'library', 'bom-ref': 'express', 'name': 'express', 'version': '4.17.1', 'components': [
                {'type': 'library', 'bom-ref': 'express|qs', 'name': 'qs', 'version': '6.7.0'},
            ]},
            {'type': 'library', 'bom-ref': 'qs', 'name': 'qs', 'version': '6.9.4'},
        ],
        'dependencies': [
            *([{'ref': 'shop', 'dependsOn': ['express', 'qs']}] if root_edges else []),
            {'ref': 'express', 'dependsOn': ['express|qs']},
            {'ref': 'express|qs', 'dependsOn': []},
            {'ref': 'qs', 'dependsOn': []},
        ],
        'vulnerabilities': [{'id': 'CVE-2022-24999', 'affects': [{'ref': 'express|qs'}]}],
    }


def test_cdx_nested_non_package_components_are_walked_but_not_imported(app, tmp_path):
    variant_id, _ = _scan(app, tmp_path, 'nested-kinds', {
        'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
        'components': [{'type': 'application', 'bom-ref': 'app', 'name': 'app', 'version': '1.0', 'components': [
            {'type': 'file', 'bom-ref': 'app|conf', 'name': 'app.conf', 'version': '1'},
            {'type': 'container', 'bom-ref': 'app|layer', 'name': 'layer', 'version': '2', 'components': [
                {'type': 'library', 'bom-ref': 'app|layer|zlib', 'name': 'zlib', 'version': '1.3'},
                {'type': 'operating-system', 'bom-ref': 'app|layer|os', 'name': 'debian', 'version': '12'},
            ]},
        ]}],
        'dependencies': [{'ref': 'app', 'dependsOn': ['app|conf', 'app|layer', 'app|layer|zlib', 'app|layer|os']}],
        'vulnerabilities': [
            {'id': 'CVE-2024-0001', 'affects': [{'ref': 'app|conf'}]},
            {'id': 'CVE-2022-37434', 'affects': [{'ref': 'app|layer|zlib'}]},
        ],
    }, 'cdx')
    graph = app.test_client().get(f'/api/package-dependencies?variant_id={variant_id}').json['documents'][0]
    assert {package['id'] for package in graph['packages']} == {'app@1.0', 'debian@12', 'zlib@1.3'}
    assert [(edge['package_id'], edge['dependency_id']) for edge in graph['edges']] == [
        ('app@1.0', 'debian@12'), ('app@1.0', 'zlib@1.3'),
    ]
    assert sorted(db.session.execute(
        db.select(Finding.vulnerability_id, Package.name).join(Package, Package.id == Finding.package_id)
    ).all()) == [('CVE-2022-37434', 'zlib')]


@pytest.mark.parametrize('root_type,root_edges,root_imported', [
    ('container', True, False),
    ('application', False, False),
    ('application', True, True),
])
def test_cdx_inventory_nested_under_the_root_is_imported_whether_or_not_the_root_is(
        app, tmp_path, root_type, root_edges, root_imported):
    variant_id, _ = _scan(app, tmp_path, 'image', {
        'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'version': 1,
        'metadata': {'component': {
            'type': root_type, 'bom-ref': 'image', 'name': 'image', 'version': '1.0', 'components': [
                {'type': 'library', 'bom-ref': 'app', 'name': 'app', 'version': '2.0'},
                {'type': 'library', 'bom-ref': 'lib', 'name': 'lib', 'version': '3.0', 'components': [
                    {'type': 'library', 'bom-ref': 'lib|zlib', 'name': 'zlib', 'version': '1.3'},
                ]},
            ],
        }},
        'dependencies': [
            *([{'ref': 'image', 'dependsOn': ['app']}] if root_edges else []),
            {'ref': 'app', 'dependsOn': ['lib']},
            {'ref': 'lib', 'dependsOn': ['lib|zlib']},
        ],
        'vulnerabilities': [{'id': 'CVE-2022-37434', 'affects': [{'ref': 'lib|zlib'}]}],
    }, 'cdx')
    graph = app.test_client().get(f'/api/package-dependencies?variant_id={variant_id}').json['documents'][0]
    children = {'app@2.0', 'lib@3.0', 'zlib@1.3'}
    assert {package['id'] for package in graph['packages']} == children | ({'image@1.0'} if root_imported else set())
    expected = [('app@2.0', 'lib@3.0')] + ([('image@1.0', 'app@2.0')] if root_imported else []) + [
        ('lib@3.0', 'zlib@1.3'),
    ]
    assert [(edge['package_id'], edge['dependency_id']) for edge in graph['edges']] == expected
    assert db.session.execute(
        db.select(Package.name).join(Finding, Finding.package_id == Package.id)
        .where(Finding.vulnerability_id == 'CVE-2022-37434')
    ).scalars().all() == ['zlib']


@pytest.mark.parametrize('root_type,root_edges,root_imported', [
    ('application', True, True),
    ('library', True, True),
    ('container', True, False),
    ('application', False, False),
])
def test_cdx_nested_components_and_dependency_root_are_imported(
        app, tmp_path, root_type, root_edges, root_imported):
    variant_id, _ = _scan(app, tmp_path, 'bundled', _cdx_bundled(root_type, root_edges), 'cdx')
    graph = app.test_client().get(f'/api/package-dependencies?variant_id={variant_id}').json['documents'][0]
    nested = {'express@4.17.1', 'qs@6.7.0', 'qs@6.9.4'}
    assert {package['id'] for package in graph['packages']} == nested | ({'shop@11.1.2'} if root_imported else set())
    expected = [('express@4.17.1', 'qs@6.7.0')]
    if root_imported:
        expected += [('shop@11.1.2', 'express@4.17.1'), ('shop@11.1.2', 'qs@6.9.4')]
    assert [(edge['package_id'], edge['dependency_id']) for edge in graph['edges']] == expected
    assert db.session.execute(
        db.select(Package.version).join(Finding, Finding.package_id == Package.id)
        .where(Finding.vulnerability_id == 'CVE-2022-24999')
    ).scalars().all() == ['6.7.0']


@pytest.mark.parametrize('version', [4, 5, 6])
def test_scoped_cdx_export_import_cycles_preserve_dependencies(app, tmp_path, version):
    from src.helpers.export_scope import compute_export_scope
    from src.views.cyclonedx import CycloneDx

    def edges(variant_id):
        documents = app.test_client().get(f'/api/package-dependencies?variant_id={variant_id}').json['documents']
        return [(edge['package_id'], edge['dependency_id']) for document in documents for edge in document['edges']]

    variant_id, _ = _scan(app, tmp_path, 'bundled', _cdx_bundled(), 'cdx')
    # The same packages depend on each other in another variant only; that edge must not leak.
    _scan(app, tmp_path, 'other', {
        'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'version': 1,
        'components': [{'type': 'library', 'bom-ref': name, 'name': name, 'version': release}
                       for name, release in (('express', '4.17.1'), ('qs', '6.9.4'))],
        'dependencies': [{'ref': 'qs', 'dependsOn': ['express']}],
    }, 'cdx')
    expected = [('express@4.17.1', 'qs@6.7.0'), ('shop@11.1.2', 'express@4.17.1'), ('shop@11.1.2', 'qs@6.9.4')]
    assert edges(variant_id) == expected

    for index in range(2):
        db.session.remove()
        controllers = ControllersCache(scope=compute_export_scope(variant_id=variant_id))
        controllers.packages._preload_cache()
        exporter = CycloneDx(controllers)
        exported = json.loads(exporter.output_as_json(version))
        names = {component['bom-ref']: f"{component['name']}@{component['version']}"
                 for component in exported['components']}
        assert sorted((names[entry['ref']], names[target]) for entry in exported['dependencies']
                      for target in entry.get('dependsOn', [])) == expected
        assert len(exported['dependencies']) == len(exported['components'])
        # Leaves are declared by the exporter itself, not only by the library's deprecated Bom.validate().
        exporter.register_dependencies()
        assert {entry.ref.value for entry in exporter.sbom.dependencies} == {
            component.bom_ref.value for component in exporter.sbom.components}
        path = tmp_path / f'cycle-{index}.cdx.json'
        path.write_text(json.dumps(exported))
        scan_id = Scan.create('SBOM', variant_id).id
        SBOMDocument.create(str(path), path.name, scan_id, format='cdx')
        read_inputs(ControllersCache(), scan_id)
        assert edges(variant_id) == expected

    global_controllers = ControllersCache()
    global_controllers.packages._preload_cache()
    exported = json.loads(CycloneDx(global_controllers).output_as_json(version))
    names = {component['bom-ref']: component['name'] + '@' + component['version'] for component in exported['components']}
    assert sorted((names[entry['ref']], names[target]) for entry in exported['dependencies']
                  for target in entry.get('dependsOn', [])) == sorted(expected + [('qs@6.9.4', 'express@4.17.1')])
    assert not any(entry.get('dependsOn') for entry in json.loads(
        CycloneDx(ControllersCache()).output_as_json(version)).get('dependencies', []))


def test_migration_creates_composite_membership_constraints(app):
    from importlib import import_module
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    migration = import_module('src.migrations.versions.d8e2a1c7b9f0_add_package_dependencies')
    with app.app_context(), db.engine.begin() as connection:
        PackageDependency.__table__.drop(connection)
        context = MigrationContext.configure(connection)
        with Operations.context(context):
            migration.upgrade()
            keys = inspect(connection).get_foreign_keys('package_dependencies')
            assert sum(key['referred_table'] == 'sbom_packages' for key in keys) == 1
            assert any(key['referred_table'] == 'packages' for key in keys)
            migration.downgrade()
        assert 'package_dependencies' not in inspect(connection).get_table_names()


def test_migration_flags_only_documents_of_scans_with_recorded_edges(app, tmp_path):
    from importlib import import_module
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    _, parsed_scan_id = _scan(app, tmp_path, 'parsed', _spdx3())
    _, legacy_scan_id = _scan(app, tmp_path, 'legacy', {'@graph': [{'type': 'CreationInfo', 'specVersion': '3.0.1'}]})
    with app.app_context():
        SBOMDocument.create(str(tmp_path / 'parsed-vex.json'), 'parsed-vex.json', parsed_scan_id, format='openvex')
        db.session.remove()
        migration = import_module('src.migrations.versions.cc5359c88dd2_flag_recorded_sbom_dependencies')
        with db.engine.begin() as connection:
            with Operations.context(MigrationContext.configure(connection)):
                migration.downgrade()
                assert 'dependencies_recorded' not in {
                    column['name'] for column in inspect(connection).get_columns('sbom_documents')}
                migration.upgrade()
            flags = connection.execute(text('SELECT source_name, dependencies_recorded FROM sbom_documents')).all()
        assert sorted(flags) == [('legacy.json', 0), ('parsed-vex.json', 1), ('parsed.json', 1)]
