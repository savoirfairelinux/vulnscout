import socket
from types import SimpleNamespace

import pytest

from src.routes import agent_skills
from src.routes.agent_skills import ASSESS, REVIEW


def _skills(tmp_path):
    root = tmp_path / "skills"
    for name in ("cve-assessment", "assessment-review", "sbom-dependencies"):
        (root / name).mkdir(parents=True)
        (root / name / "SKILL.md").write_text(f"---\nname: {name}\n---\n")
    (root / "README.md").write_text("readme")
    return root


def _decide(handler, kind, **fields):
    return handler(SimpleNamespace(kind=kind, **fields), {}).kind


def _resolve_to(monkeypatch, *addresses):
    def fake(host, port, *args, **kwargs):
        if not addresses:
            raise socket.gaierror("unresolvable")
        return [(socket.AF_INET6 if ":" in a else socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, 0))
                for a in addresses]
    monkeypatch.setattr(agent_skills.socket, "getaddrinfo", fake)


def test_profiles_expose_only_their_writes():
    assert agent_skills.PROFILES == {"assess": ASSESS, "review": REVIEW}
    assert ASSESS.skill == "cve-assessment" and ASSESS.skills == ("cve-assessment",)
    assert set(ASSESS.write_tools) == {"write_assessment", "update_ai_assessment"}
    assert REVIEW.skill == "assessment-review" and set(REVIEW.skills) == {"assessment-review", "cve-assessment"}
    assert REVIEW.write_tools == ("write_assessment_review",)


def test_skills_path_uses_override_then_repository(monkeypatch, tmp_path):
    root = _skills(tmp_path)
    monkeypatch.setenv("VULNSCOUT_SKILLS_PATH", str(root))
    assert agent_skills.skills_path() == root.resolve()
    monkeypatch.setenv("VULNSCOUT_SKILLS_PATH", str(tmp_path / "missing"))
    assert agent_skills.skills_path() is None
    monkeypatch.delenv("VULNSCOUT_SKILLS_PATH")
    assert (agent_skills.skills_path() / "cve-assessment" / "SKILL.md").is_file()


@pytest.mark.parametrize("value, enabled", [(None, True), ("1", True), ("0", False), ("False", False),
                                            ("no", False), (" OFF ", False)])
def test_web_access_flag(monkeypatch, value, enabled):
    if value is None:
        monkeypatch.delenv("VULNSCOUT_AGENT_WEB_ACCESS", raising=False)
    else:
        monkeypatch.setenv("VULNSCOUT_AGENT_WEB_ACCESS", value)
    assert agent_skills.web_access_enabled() is enabled


def test_missing_and_disabled_skills(tmp_path):
    root = _skills(tmp_path)
    assert agent_skills.missing_skills(root, REVIEW) == []
    assert agent_skills.disabled_skills(root, ASSESS) == ["assessment-review", "sbom-dependencies"]
    assert agent_skills.disabled_skills(root, REVIEW) == ["sbom-dependencies"]
    (root / "cve-assessment" / "SKILL.md").unlink()
    assert agent_skills.missing_skills(root, REVIEW) == ["cve-assessment"]


def test_reads_are_confined_to_the_skills_root(tmp_path):
    root = _skills(tmp_path)
    (tmp_path / "secret.txt").write_text("secret")
    (root / "cve-assessment" / "escape").symlink_to(tmp_path / "secret.txt")
    handler = agent_skills.skill_permissions(root, True)
    inside = str(root / "cve-assessment" / "SKILL.md")
    assert _decide(handler, "read", path=inside, resolved_path=None) == "approve-once"
    assert _decide(handler, "read", path=str(tmp_path / "secret.txt"), resolved_path=None) == "reject"
    assert _decide(handler, "read", path=f"{root}/cve-assessment/../../secret.txt", resolved_path=None) == "reject"
    assert _decide(handler, "read", path=str(root / "cve-assessment" / "escape"), resolved_path=None) == "reject"
    assert _decide(handler, "read", path=inside, resolved_path=str(tmp_path / "secret.txt")) == "reject"
    assert _decide(handler, "read", path="/etc/hostname", resolved_path=None) == "reject"
    assert _decide(handler, "read", path=None, resolved_path=None) == "reject"


def test_public_urls_only(monkeypatch, tmp_path):
    handler = agent_skills.skill_permissions(_skills(tmp_path), True)
    _resolve_to(monkeypatch, "93.184.215.14", "2606:4700::1")
    assert _decide(handler, "url", url="https://nvd.nist.gov/vuln/detail/CVE-2024-0001") == "approve-once"
    assert _decide(handler, "url", url="ftp://nvd.nist.gov/x") == "reject"
    assert _decide(handler, "url", url="https:///nohost") == "reject"
    for address in ("127.0.0.1", "::1", "10.0.0.1", "169.254.169.254", "100.64.0.1", "0.0.0.0",
                    "224.0.0.1", "ff02::1", "::ffff:127.0.0.1", "::127.0.0.1", "64:ff9b::7f00:1",
                    "64:ff9b:1::a00:1", "fec0::1"):
        _resolve_to(monkeypatch, address)
        assert _decide(handler, "url", url="https://example.org/") == "reject", address
    _resolve_to(monkeypatch, "93.184.215.14", "192.168.1.10")
    assert _decide(handler, "url", url="https://mixed.example/") == "reject"
    _resolve_to(monkeypatch)
    assert _decide(handler, "url", url="https://unresolvable.example/") == "reject"


def test_urls_rejected_when_web_disabled(monkeypatch, tmp_path):
    _resolve_to(monkeypatch, "93.184.215.14")
    handler = agent_skills.skill_permissions(_skills(tmp_path), False)
    assert _decide(handler, "url", url="https://nvd.nist.gov/") == "reject"


@pytest.mark.parametrize("kind", ["shell", "write", "memory", "hook", "custom-tool", "extension-management"])
def test_other_requests_are_rejected_and_mcp_approved(tmp_path, kind):
    handler = agent_skills.skill_permissions(_skills(tmp_path), True)
    assert _decide(handler, kind) == "reject"
    assert _decide(handler, "mcp", server_name="vulnscout", tool_name="get_vulnerability") == "approve-once"


@pytest.mark.parametrize("web, builtins", [(True, ["skill", "view", "web_fetch"]), (False, ["skill", "view"])])
def test_session_options(tmp_path, web, builtins):
    root = _skills(tmp_path)
    options = agent_skills.session_options(REVIEW, root, web, ("get_vulnerability", "write_assessment_review"))
    assert options["available_tools"] == ["mcp:vulnscout-get_vulnerability", "mcp:vulnscout-write_assessment_review",
                                          *(f"builtin:{name}" for name in builtins)]
    assert options["enable_skills"] is True
    assert options["skill_directories"] == [str(root)]
    assert options["disabled_skills"] == ["sbom-dependencies"]
    [custom] = options["custom_agents"]
    assert options["agent"] == custom["name"] == "vulnscout-review"
    assert custom["skills"] == ["assessment-review", "cve-assessment"] and custom["infer"] is False
    assert str(root) in custom["prompt"] and "web_fetch" in custom["prompt"]
    assert options["system_message"] == {"mode": "append", "content": agent_skills.PROFILE_SYSTEM_MESSAGE}
    assert callable(options["on_permission_request"])


def test_profile_message():
    assert agent_skills.profile_message(ASSESS, True, "Assess CVE-1") == "Use the cve-assessment skill.\n\nAssess CVE-1"
    offline = agent_skills.profile_message(REVIEW, False, "Review a1")
    assert offline.startswith("Use the assessment-review skill.\n")
    assert "Web research is unavailable" in offline and offline.endswith("\n\nReview a1")
