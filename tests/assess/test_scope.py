import pytest

from vulnscout_assess.scope import Scope, ScopeError, Variant, resolve_scope


def test_no_scope_resolves_default_project_and_variant(client):
    assert resolve_scope(client, None, None) == Scope("default", (Variant("v-def", "default"),))


def test_project_only_resolves_all_project_variants(client):
    scope = resolve_scope(client, "Proj", None)

    assert scope == Scope("Proj", (Variant("v-x86", "x86"), Variant("v-arm", "arm")))


def test_project_and_variant_resolves_single_variant(client):
    assert resolve_scope(client, "Proj", "arm") == Scope("Proj", (Variant("v-arm", "arm"),))


def test_variant_only_uses_default_project(client):
    assert resolve_scope(client, None, "release") == Scope("default", (Variant("v-rel", "release"),))


def test_unknown_project_raises(client):
    with pytest.raises(ScopeError, match="project not found: Nope"):
        resolve_scope(client, "Nope", None)


def test_unknown_variant_raises(client):
    with pytest.raises(ScopeError, match="variant not found: mips"):
        resolve_scope(client, "Proj", "mips")


def test_project_without_variants_raises(client):
    client.variants["p-proj"] = []

    with pytest.raises(ScopeError, match="project has no variants: Proj"):
        resolve_scope(client, "Proj", None)
