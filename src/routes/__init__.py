#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from .packages import init_app as init_pkg_app
from .vulnerabilities import init_app as init_vuln_app
from .assessments import init_app as init_assess_app
from .documents import init_app as init_doc_app
from .patch_finder import init_app as init_patch_finder_app
from .nvd_progress import init_app as init_nvd_progress_app
from .epss_progress import init_app as init_epss_progress_app
from .project import init_app as init_project_app
from .variant import init_app as init_variant_app
from .scans import init_app as init_scans_app
from .config import init_app as init_config_app
from .notifications import init_app as init_notifications_app
from .frontpage import init_app as init_front_app


def init_app(app):
    init_pkg_app(app)
    init_vuln_app(app)
    init_assess_app(app)
    init_doc_app(app)
    init_patch_finder_app(app)
    init_nvd_progress_app(app)
    init_epss_progress_app(app)
    init_project_app(app)
    init_variant_app(app)
    init_scans_app(app)
    init_config_app(app)
    init_notifications_app(app)
    # keep front endpoint at the end
    init_front_app(app)
    return app
