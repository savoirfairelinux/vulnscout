"""
Helpers for fuzzy version comparison used by the copy-assessments feature.

``versions_match(v1, v2, precision)`` returns True when the first
``precision`` numeric components of both version strings are equal.

precision=1  →  only the major component must match  (e.g. 6.5 vs 6.9 ✓, 6.5 vs 7.0 ✗)
precision=2  →  major + minor must match             (e.g. 6.5.1 vs 6.5.9 ✓, 6.5 vs 6.7 ✗)

Parsing strategy (most-specific first):
1. Try ``semver`` (already a project dependency) with optional minor/patch.
2. Fall back to splitting on "." and comparing integer prefixes.
"""

from __future__ import annotations

import re

import semver


def _semver_components(version_str: str) -> tuple[int, ...]:
    """Return (major, minor, patch) from a semver-parseable string."""
    v = semver.Version.parse(version_str, optional_minor_and_patch=True)
    return (v.major, v.minor, v.patch)


def _split_components(version_str: str) -> tuple[int, ...]:
    """
    Fallback: split on "." and "+" / "-" delimiters and collect leading
    integer parts.  Non-numeric trailing parts are ignored.
    """
    # Strip build metadata and pre-release suffixes first
    clean = re.split(r"[+\-]", version_str, maxsplit=1)[0]
    parts: list[int] = []
    for segment in clean.split("."):
        m = re.match(r"^(\d+)", segment)
        if m:
            parts.append(int(m.group(1)))
        else:
            break
    return tuple(parts)


def _parse_components(version_str: str) -> tuple[int, ...]:
    """Return a tuple of numeric version components, at least length 1."""
    if not version_str:
        return (0,)
    try:
        return _semver_components(version_str)
    except ValueError:
        components = _split_components(version_str)
        if not components:
            return (0,)
        return components


def versions_match(v1: str | None, v2: str | None, precision: int) -> bool:
    """
    Return True when the two version strings agree on the first ``precision``
    numeric components.

    None or empty strings are treated as "0".

    Examples (precision=1):
        "6.5"  vs "6.7"  → True
        "6.5"  vs "7.0"  → False

    Examples (precision=2):
        "6.5.1" vs "6.5.9" → True
        "6.5"   vs "6.7"   → False
    """
    if precision <= 0:
        return True

    c1 = _parse_components(v1 or "")
    c2 = _parse_components(v2 or "")

    for i in range(precision):
        n1 = c1[i] if i < len(c1) else 0
        n2 = c2[i] if i < len(c2) else 0
        if n1 != n2:
            return False
    return True
