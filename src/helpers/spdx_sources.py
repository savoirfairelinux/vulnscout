# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Resolve explicit source provenance without treating dependency toolchains as sources."""

from collections import defaultdict
import uuid

from .package_versions import git_revision_from_url

SourceKey = tuple[str, str]
ScopedSourceKey = tuple[uuid.UUID | None, str, str]


class SPDXSources:
    def __init__(self) -> None:
        self.packages: dict[ScopedSourceKey, set[tuple[uuid.UUID | None, str]]] = defaultdict(set)
        self.urls: dict[ScopedSourceKey, set[str]] = defaultdict(set)
        self.origins: dict[ScopedSourceKey, set[ScopedSourceKey]] = defaultdict(set)
        self.inputs: set[tuple[ScopedSourceKey, ScopedSourceKey]] = set()
        self.builds: set[ScopedSourceKey] = set()
        self.build_outputs: set[tuple[ScopedSourceKey, ScopedSourceKey]] = set()
        self.build_inputs: set[tuple[ScopedSourceKey, ScopedSourceKey]] = set()

    def record(self, scan_id: uuid.UUID | None, references: dict[SourceKey, str],
               urls: dict[SourceKey, str], derivations: set[tuple[SourceKey, SourceKey]],
               inputs: set[tuple[SourceKey, SourceKey]], builds: set[SourceKey] | None = None,
               document_id: uuid.UUID | None = None) -> None:
        for key, package_id in references.items():
            self.packages[(scan_id, *key)].add((document_id, package_id))
        for key, url in urls.items():
            if git_revision_from_url(url) is not None:
                self.urls[(scan_id, *key)].add(url)
        if builds is None:
            for derived, origin in derivations:
                self.origins[(scan_id, *derived)].add((scan_id, *origin))
            self.inputs.update(((scan_id, *derived), (scan_id, *origin)) for derived, origin in inputs)
        else:
            self.builds.update((scan_id, *key) for key in builds)
            self.build_outputs.update(((scan_id, *derived), (scan_id, *origin)) for derived, origin in derivations)
            self.build_inputs.update(((scan_id, *derived), (scan_id, *origin)) for derived, origin in inputs)

    def resolve(self) -> dict[tuple[uuid.UUID | None, str], set[str]]:
        # Only direct source URLs count as build inputs. A compiler's own source
        # revision must not be propagated through BUILD_DEPENDENCY_OF to its users.
        origins = {key: set(values) for key, values in self.origins.items()}
        for derived, origin in self.build_outputs:
            if origin in self.builds:
                origins.setdefault(derived, set()).add(origin)
        inputs = self.inputs | {(derived, origin) for derived, origin in self.build_inputs if derived in self.builds}
        for derived, origin in inputs:
            if origin in self.urls:
                origins.setdefault(derived, set()).add(origin)
        result: dict[tuple[uuid.UUID | None, str], set[str]] = defaultdict(set)
        for key, packages in self.packages.items():
            pending = [key]
            seen: set[ScopedSourceKey] = set()
            while pending:
                current = pending.pop()
                if current in seen:
                    continue
                seen.add(current)
                for package in packages:
                    result[package].update(self.urls.get(current, ()))
                pending.extend(origins.get(current, ()))
        return result
