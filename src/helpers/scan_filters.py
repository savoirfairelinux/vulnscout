# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Filters applied to SBOM components before handing them to scanners.

Kernel companion packages (``kernel-*``: ``kernel-module-*``, ``kernel-modules``,
``kernel-image-*``, ``kernel-devicetree``, ``kernel-6.6.116`` …) are expanded
one-per-output in SPDX 3 SBOMs, inflating a typical 50-100 package set to 1000+
entries.  They all inherit the base kernel's ``linux`` / ``linux_kernel`` CPE, so
feeding them to the vulnerability scanners (Grype, NVD CPE, OSV) attributes the
entire kernel CVE set to every one of them — slow and useless.  They are kept
as-is in the SBOM views, but excluded from scanner inputs; the real kernel recipe
(named ``linux-*``, e.g. ``linux-stm32mp``) is unaffected and still scanned.
"""

from __future__ import annotations

from typing import Iterable, List, TypeVar

# Component names starting with this prefix are kernel recipe companion packages
# and are excluded from scanner inputs.  Matches ``kernel-module-foo``,
# ``kernel-modules``, ``kernel-image-*``, ``kernel-devicetree``,
# ``kernel-6.6.116`` … without catching the real kernel recipe (``linux-*``) or
# unrelated names such as ``kernelshark``.
KERNEL_PACKAGE_PREFIX = "kernel-"

T = TypeVar("T")


def is_kernel_package_name(name: str | None) -> bool:
    """Return ``True`` when *name* denotes a kernel recipe companion package."""
    if not name:
        return False
    return name.strip().lower().startswith(KERNEL_PACKAGE_PREFIX)


def filter_scannable_packages(packages: Iterable[T]) -> List[T]:
    """Drop kernel companion packages from *packages* before scanning.

    Each item must expose a ``name`` attribute (e.g. a ``Package``).
    """
    return [pkg for pkg in packages if not is_kernel_package_name(getattr(pkg, "name", None))]
