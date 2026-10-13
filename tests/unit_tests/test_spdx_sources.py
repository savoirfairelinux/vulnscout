from uuid import uuid4

from src.helpers.spdx_sources import SPDXSources


def test_source_graph_is_cycle_safe_and_scan_scoped():
    sources = SPDXSources()
    scan = uuid4()
    source, recipe, binary = ("ns", "source"), ("ns", "recipe"), ("ns", "binary")
    url = f"git+https://example.org/lib@{'a' * 40}"
    sources.record(scan, {binary: "lib@1"}, {source: url}, {(binary, recipe), (recipe, binary)},
                   {(recipe, source)})
    sources.record(uuid4(), {binary: "other@1"}, {}, {(binary, recipe)}, {(recipe, source)})
    assert sources.resolve() == {(None, "lib@1"): {url}, (None, "other@1"): set()}


def test_shared_package_references_keep_document_and_scan_targets_separate():
    sources = SPDXSources()
    scan, first, second, other = uuid4(), uuid4(), uuid4(), uuid4()
    ref = ("ns", "lib")
    url = f"git+https://example.org/lib@{'a' * 40}"
    sources.record(scan, {ref: "lib@1"}, {ref: url}, set(), set(), document_id=first)
    sources.record(scan, {ref: "lib@1"}, {}, set(), set(), document_id=second)
    sources.record(uuid4(), {ref: "lib@1"}, {}, set(), set(), document_id=other)
    assert sources.resolve() == {(first, "lib@1"): {url}, (second, "lib@1"): {url}, (other, "lib@1"): set()}
