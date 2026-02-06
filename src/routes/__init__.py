#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from .packages import init_app as init_pkg_app
from .vulnerabilities import init_app as init_vuln_app
from .assessments import init_app as init_assess_app
from .documents import init_app as init_doc_app
from .patch_finder import init_app as init_patch_finder_app
from .nvd_progress import init_app as init_nvd_progress_app
from .frontpage import init_app as init_front_app


def init_app(app):
    init_pkg_app(app)
    init_vuln_app(app)
    init_assess_app(app)
    init_doc_app(app)
    init_patch_finder_app(app)
    init_nvd_progress_app(app)
    # keep front endpoint at the end
    init_front_app(app)
    return app
