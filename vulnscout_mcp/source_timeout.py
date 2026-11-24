# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Recovery guidance shared by the HTTP source client and the host-helper transport."""


def timeout_recovery(operation: str, *, upload: bool = False) -> str:
    if upload:
        return "Consult a smaller, independent reference from the same build."
    if operation == "list":
        return "Use list_codebase_children to navigate, or narrow the folder before matching filenames."
    if operation in ("read", "children", "shell"):
        return ("For a literal in a known log, use search_codebase_file. Otherwise choose a narrower "
                "artifact from the same build.")
    if operation == "search_file":
        return "Consult a smaller, independent artifact from the same build rather than repeating this search."
    return ""
