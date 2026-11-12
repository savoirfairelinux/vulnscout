# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Normalise repository URLs and PURLs to ``host/path`` identifiers.

Forge URLs (GitHub, GitLab, Bitbucket) map to ``host/owner/repo`` whatever the
page or download path; other hosts only count when the URL is explicitly Git.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from packageurl import PackageURL

SCORECARD_HOSTS = frozenset({"github.com", "gitlab.com"})
MAX_REPOSITORY_LENGTH = 255

_HOST_ALIASES = {
    "www.github.com": "github.com",
    "raw.githubusercontent.com": "github.com",
    "codeload.github.com": "github.com",
    "www.gitlab.com": "gitlab.com",
    "www.bitbucket.org": "bitbucket.org",
}
_FORGE_HOSTS = frozenset({"github.com", "gitlab.com", "bitbucket.org"})
_PURL_HOSTS = {"github": "github.com", "gitlab": "gitlab.com", "bitbucket": "bitbucket.org"}
_GITLAB_ROUTES = frozenset({
    "-", "archive", "blob", "commit", "commits", "issues", "raw", "releases", "repository", "tags", "tree",
    "uploads",
})
_GIT_SCHEMES = frozenset({"git", "ssh", "git+git", "git+http", "git+https", "git+ssh"})
_SEGMENT = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$")
_HOST = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$")
_SCP_LIKE = re.compile(r"^[\w.-]+@([\w.-]+):(?!//)(.+)$")


def normalize_repository(value: object, assume_git: bool = False) -> str | None:
    """Return the repository identifier for *value*, or ``None`` when it names no repository.

    *assume_git* accepts any host for URLs known to be Git remotes (e.g. OSV ``GIT`` ranges).
    """
    if not isinstance(value, str) or not value.strip():
        return None
    value = value.strip()
    if value.startswith("pkg:"):
        return _from_purl(value)
    return _from_url(value, assume_git)


def scorecard_supported(repository: str) -> bool:
    """Whether OpenSSF Scorecard publishes results for *repository* (``host/owner/repo`` on GitHub/GitLab)."""
    host, _, path = repository.partition("/")
    return host in SCORECARD_HOSTS and path.count("/") == 1


def _from_purl(value: str) -> str | None:
    try:
        purl = PackageURL.from_string(value)
    except ValueError:
        return None
    host = _PURL_HOSTS.get(purl.type)
    if host is not None:
        return _forge_repository(host, [*(purl.namespace or "").split("/"), purl.name])
    if purl.type == "golang" and purl.namespace:
        segments = [*purl.namespace.split("/"), purl.name]
        if segments[0].lower() in _FORGE_HOSTS:
            return _forge_repository(segments[0].lower(), segments[1:])
    return None


def _from_url(value: str, assume_git: bool) -> str | None:
    scp = _SCP_LIKE.match(value) if "://" not in value else None
    if scp is not None:
        host, path, is_git = scp.group(1).lower(), scp.group(2), True
    else:
        try:
            # Yocto SRC_URIs append ";protocol=https;branch=..." parameters.
            parts = urlsplit(value.split(";", 1)[0])
            host = parts.hostname or ""
        except ValueError:
            return None
        scheme = parts.scheme.lower()
        if scheme not in {"http", "https"} | _GIT_SCHEMES:
            return None
        path = parts.path
        is_git = assume_git or scheme in _GIT_SCHEMES or path.rstrip("/").endswith(".git")
    host = _HOST_ALIASES.get(host, host)
    if not _HOST.match(host):
        return None
    segments = [segment for segment in path.split("/") if segment]
    if host in _FORGE_HOSTS:
        return _forge_repository(host, segments)
    if not is_git or not segments:
        return None
    return _join(host, segments)


def _forge_repository(host: str, segments: list[str]) -> str | None:
    segments = [segment for segment in segments if segment]
    if host == "gitlab.com":
        end = next((index for index, segment in enumerate(segments) if index >= 2 and segment in _GITLAB_ROUTES),
                   len(segments))
        segments = segments[:end]
    else:
        segments = segments[:2]
    if len(segments) < 2:
        return None
    return _join(host, segments)


def _join(host: str, segments: list[str]) -> str | None:
    # A trailing "@<revision>" pins git+https URLs (e.g. Zephyr's west manifests).
    last = segments[-1].split("@", 1)[0]
    if last.endswith(".git"):
        last = last[:-4]
    segments = [*segments[:-1], last]
    if not all(_SEGMENT.match(segment) for segment in segments):
        return None
    repository = "/".join([host, *segments])
    return repository if len(repository) <= MAX_REPOSITORY_LENGTH else None
