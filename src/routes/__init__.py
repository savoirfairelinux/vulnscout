# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from .packages import init_app as init_pkg_app
from .vulnerabilities import init_app as init_vuln_app
from .assessments import init_app as init_assess_app
from .documents import init_app as init_doc_app
from .events import init_app as init_events_app
from .operations import init_app as init_operations_app
from .project import init_app as init_project_app
from .variant import init_app as init_variant_app
from .scans import init_app as init_scans_app
from .config import init_app as init_config_app
from .settings import init_app as init_settings_app
from .openapi import init_app as init_openapi_app
from .frontpage import init_app as init_front_app
from .context import init_app as init_context_app


def init_app(app):
    init_pkg_app(app)
    init_vuln_app(app)
    init_assess_app(app)
    init_doc_app(app)
    init_events_app(app)
    init_operations_app(app)
    init_project_app(app)
    init_variant_app(app)
    init_scans_app(app)
    init_config_app(app)
    init_settings_app(app)
    init_context_app(app)
    init_openapi_app(app)
    # keep front endpoint at the end
    init_front_app(app)
    return app
