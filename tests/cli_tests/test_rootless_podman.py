"""Opt-in real Podman regressions: VULNSCOUT_TEST_ROOTLESS_IMAGE=<local image> pytest."""

import os
from pathlib import Path
import shutil
import subprocess
import time
import uuid

import pytest


ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def rootless_image():
    image = os.environ.get("VULNSCOUT_TEST_ROOTLESS_IMAGE")
    if not image:
        pytest.skip("Set VULNSCOUT_TEST_ROOTLESS_IMAGE to a local VulnScout image")
    result = subprocess.run(
        ["podman", "info", "--format", "{{.Host.Security.Rootless}}"],
        capture_output=True, text=True, check=True,
    )
    assert result.stdout.strip() == "true", "These regressions require rootless Podman"
    return image


@pytest.mark.parametrize("cache_mode", [0o700, 0o755])
def test_recovers_real_legacy_cache(rootless_image, tmp_path, cache_mode):
    cache = tmp_path / "cache"
    cache.mkdir(mode=cache_mode)
    config = cache / "config.env"
    original = b"VERBOSE_MODE=false\n"
    config.write_bytes(original)
    config.chmod(0o600)
    subprocess.run(
        ["podman", "unshare", "chown", "1000:1000", str(config), str(cache)],
        check=True,
    )
    try:
        if cache_mode == 0o700:
            assert not os.access(config, os.F_OK)
        result = subprocess.run(
            ["bash", str(ROOT / "vulnscout"), "--help"],
            env={**os.environ, "VULNSCOUT_CACHE_DIR": str(cache)},
            capture_output=True, text=True, check=True,
        )
        assert "Usage: vulnscout" in result.stdout
        assert config.read_bytes() == original
        assert config.stat().st_uid == os.getuid()
        assert config.stat().st_gid == os.getgid()
        assert config.stat().st_mode & 0o777 == 0o600
        assert cache.stat().st_uid == os.getuid()
        assert cache.stat().st_mode & 0o777 == cache_mode
    finally:
        subprocess.run(
            ["podman", "unshare", "chown", "0:0", str(cache), str(config)],
            check=True,
        )


def test_real_daemon_reads_private_config_and_preserves_mounts(rootless_image, tmp_path):
    cache = tmp_path / "cache"
    outputs = tmp_path / "outputs"
    cache.mkdir(mode=0o700)
    outputs.mkdir(mode=0o700)
    config = cache / "config.env"
    original = f"USER_UID={os.getuid()}\nUSER_GID={os.getgid()}\nVERBOSE_MODE=false\n"
    config.write_text(original)
    config.chmod(0o600)
    legacy_data = cache / "legacy-data"
    legacy_data.write_text("preserved")
    subprocess.run(
        ["podman", "unshare", "chown", "1000:1000", str(legacy_data)],
        check=True,
    )
    entrypoint = tmp_path / "entrypoint.sh"
    shutil.copyfile(ROOT / "src" / "entrypoint.sh", entrypoint)
    entrypoint.chmod(0o755)
    container = f"vulnscout-rootless-test-{uuid.uuid4().hex}"
    try:
        subprocess.run(
            [
                "podman", "run", "--pull=never", "--network=none", "-d",
                "--name", container, "--userns=keep-id:uid=0,gid=0", "--user=0:0",
                "-e", "VULNSCOUT_ROOTLESS_PODMAN=true",
                "-e", "SBOM_CVE_CHECK_AUTO_UPDATE=0",
                "-v", f"{cache}:/cache/vulnscout:Z",
                "-v", f"{outputs}:/scan/outputs:Z",
                "-v", f"{config}:/etc/vulnscout/config.env:Z",
                "-v", f"{entrypoint}:/scan/src/entrypoint.sh:ro,Z",
                rootless_image, "daemon",
            ],
            capture_output=True, text=True, check=True,
        )
        logs = ""
        for _ in range(50):
            logs = subprocess.run(
                ["podman", "logs", container],
                capture_output=True, text=True, check=True,
            ).stdout
            if "VulnScout ready." in logs:
                break
            running = subprocess.run(
                ["podman", "inspect", "--format", "{{.State.Running}}", container],
                capture_output=True, text=True, check=True,
            ).stdout.strip()
            if running != "true":
                break
            time.sleep(0.1)
        assert "VulnScout ready." in logs
        assert config.read_text() == original
        subprocess.run(
            [
                "podman", "exec", container, "/scan/src/entrypoint.sh",
                "--config", "VERBOSE_MODE", "true",
            ],
            capture_output=True, text=True, check=True,
        )
        subprocess.run(
            [
                "podman", "exec", container, "sh", "-c",
                "touch /cache/vulnscout/probe /scan/outputs/probe",
            ],
            capture_output=True, text=True, check=True,
        )
        assert "VERBOSE_MODE=true" in config.read_text()
        assert config.stat().st_mode & 0o777 == 0o600
        assert legacy_data.read_text() == "preserved"
        for path in (cache, outputs, config, legacy_data, cache / "probe", outputs / "probe"):
            assert path.stat().st_uid == os.getuid()
            assert path.stat().st_gid == os.getgid()
    finally:
        subprocess.run(["podman", "rm", "-f", container], capture_output=True, check=True)
