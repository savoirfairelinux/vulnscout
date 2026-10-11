from vulnscout_assess.precheck import missing_variants
from vulnscout_assess.scope import Variant

X86 = Variant("v-x86", "x86")
ARM = Variant("v-arm", "arm")


def test_all_variants_missing_without_assessments(client):
    assert missing_variants(client, "CVE-2026-0001", (X86, ARM)) == (X86, ARM)


def test_variant_with_ai_assessment_is_not_missing(client):
    client.assessments["CVE-2026-0001"] = [{"origin": "ai", "variant_ids": ["v-x86"]}]

    assert missing_variants(client, "CVE-2026-0001", (X86, ARM)) == (ARM,)


def test_custom_assessment_does_not_count(client):
    client.assessments["CVE-2026-0001"] = [{"origin": "custom", "variant_ids": ["v-x86", "v-arm"]}]

    assert missing_variants(client, "CVE-2026-0001", (X86, ARM)) == (X86, ARM)


def test_fully_covered_returns_empty(client):
    client.assessments["CVE-2026-0001"] = [{"origin": "ai", "variant_ids": ["v-x86", "v-arm"]}]

    assert missing_variants(client, "CVE-2026-0001", (X86, ARM)) == ()


def test_queries_assessments_once_per_cve(client):
    missing_variants(client, "CVE-2026-0001", (X86, ARM))

    assert client.assessment_calls == ["CVE-2026-0001"]
