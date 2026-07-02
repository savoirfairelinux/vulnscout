# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from .progress_tracker import ProgressTracker

EUVDProgressTracker = ProgressTracker(
    default_phase="euvd_enrichment",
    completed_message="EUVD enrichment completed successfully",
)
