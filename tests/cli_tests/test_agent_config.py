"""Agent credentials stay in the mounted file, not CLI output or container metadata."""

import os
from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[2]
ENTRYPOINT = ROOT / "src" / "entrypoint.sh"
WRAPPER = ROOT / "vulnscout"


@pytest.fixture
def config_environment(tmp_path):
    cache = tmp_path / "cache"
    cache.mkdir()
    config = cache / "config.env"
    config.write_text(
        "AI_PROVIDER=openai\nAI_AUTH_CREDENTIALS='private key'\n"
        "AI_MODEL=model\nAI_BASE_URL=https://example.org/v1\nNVD_API_KEY=nvd-private\n"
    )
    config.chmod(0o666)
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    engine = fake_bin / "podman"
    engine.write_text('#!/bin/bash\nprintf "%s\\n" "$@" >> "$ENGINE_LOG"\n')
    engine.chmod(0o755)
    return config, {
        **os.environ,
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "VULNSCOUT_CACHE_DIR": str(cache),
        "VULNSCOUT_OUTPUTS_DIR": str(tmp_path / "outputs"),
        "VULNSCOUT_CONFIG": str(config),
        "ENGINE_LOG": str(tmp_path / "engine.log"),
    }


@pytest.mark.parametrize("script", [WRAPPER, ENTRYPOINT], ids=["wrapper", "entrypoint"])
def test_config_list_redacts_agent_credentials(config_environment, script):
    config, environment = config_environment
    result = subprocess.run(
        ["bash", str(script), "--config-list"], env=environment,
        cwd=ROOT, capture_output=True, text=True, check=True,
    )
    assert "AI_AUTH_CREDENTIALS=****" in result.stdout
    assert "private key" not in result.stdout
    assert "nvd-private" not in result.stdout


def test_wrapper_uses_mounted_file_instead_of_agent_environment(config_environment):
    config, environment = config_environment
    subprocess.run(
        ["bash", str(WRAPPER), "--start"], env=environment,
        cwd=ROOT, capture_output=True, text=True, check=True,
    )
    arguments = Path(environment["ENGINE_LOG"]).read_text().splitlines()
    assert any(f"{config}:/etc/vulnscout/config.env" in arg for arg in arguments)
    assert not any(arg.startswith(("AI_PROVIDER=", "AI_AUTH_CREDENTIALS=", "AI_MODEL=", "AI_BASE_URL="))
                   for arg in arguments)
    assert config.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("signed_out", [False, True])
def test_entrypoint_startup_overrides_stale_agent_environment(config_environment, signed_out):
    config, environment = config_environment
    environment.update(AI_PROVIDER="github", AI_AUTH_CREDENTIALS="stale-token", AI_MODEL="stale-model")
    if signed_out:
        config.write_text("")
    startup = ENTRYPOINT.read_text().split("# The sbom-cve-check", 1)[0]
    result = subprocess.run(
        ["bash", "-c", startup + '\nprintf "%s|%s|%s" "${AI_PROVIDER:-}" '
         '"${AI_AUTH_CREDENTIALS:-}" "${AI_MODEL:-}"'],
        env=environment, cwd=ROOT, capture_output=True, text=True, check=True,
    )
    assert result.stdout == ("||" if signed_out else "openai|private key|model")
