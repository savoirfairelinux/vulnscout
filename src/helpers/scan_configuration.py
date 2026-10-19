"""Project scan preferences persisted in the VulnScout cache."""

import fcntl
import json
import os
import tempfile
from pathlib import Path

DEFAULT_NATIVE_EXCEPTIONS = ["gcc-native", "g++-native", "cmake-native"]


def validate_scan_configuration(value: object) -> dict:
    if not isinstance(value, dict) or not isinstance(value.get("exclude_native"), bool):
        raise ValueError("exclude_native must be a boolean")
    names = value.get("native_package_exceptions")
    if not isinstance(names, list) or len(names) > 1000 or any(
        not isinstance(name, str) or len(name) > 255
        or not name.strip().lower().endswith("-native") for name in names
    ):
        raise ValueError("native_package_exceptions must be a list of native package names")
    return {
        "exclude_native": value["exclude_native"],
        "native_package_exceptions": sorted({name.strip().lower() for name in names}),
    }


def _configuration_path() -> Path:
    cache = Path(os.environ.get("VULNSCOUT_CACHE_DIR", "/cache/vulnscout"))
    return cache / "project-scan.json"


def _read_configurations(path: Path) -> dict:
    try:
        configurations = json.loads(path.read_text())
    except FileNotFoundError:
        configurations = {}
    if not isinstance(configurations, dict):
        raise ValueError("Project scan configurations must be an object keyed by project name")
    defaults = {
        "exclude_native": True,
        "native_package_exceptions": list(DEFAULT_NATIVE_EXCEPTIONS),
    }
    legacy_projects_entry = configurations.get("projects")
    legacy_named_projects = isinstance(legacy_projects_entry, dict) and isinstance(
        legacy_projects_entry.get("exclude_native"), bool,
    )
    if "global" in configurations and "projects" in configurations and not legacy_named_projects:
        if set(configurations) != {"global", "projects"} or not isinstance(configurations["projects"], dict):
            raise ValueError("Scan configuration must contain global preferences and a projects object")
        return {
            "global": validate_scan_configuration(configurations["global"]),
            "projects": {
                name: validate_scan_configuration(value) for name, value in configurations["projects"].items()
            },
        }
    # Read the original project-name mapping; the next save upgrades it atomically.
    return {
        "global": defaults,
        "projects": {name: validate_scan_configuration(value) for name, value in configurations.items()},
    }


def read_scan_configuration(project_name: str | None = None) -> dict:
    configurations = _read_configurations(_configuration_path())
    if project_name is None:
        return configurations["global"]
    return configurations["projects"].get(project_name, configurations["global"])


def write_scan_configuration(project_name: str | None, value: object) -> dict:
    configuration = validate_scan_configuration(value)
    path = _configuration_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    # Lock a stable sidecar because atomic replacement changes the JSON file's inode.
    with path.with_suffix(".lock").open("a") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            configurations = _read_configurations(path)
            if project_name is None:
                configurations["global"] = configuration
            else:
                configurations["projects"][project_name] = configuration
            descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=".project-scan-")
            try:
                with os.fdopen(descriptor, "w") as handle:
                    json.dump(configurations, handle, indent=2)
                    handle.write("\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, path)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
    return configuration
