#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# This python script will run a Flask server to serve the web API.
# Data exposed by API come from files generated by a previous run of merger_ci.py
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from ..helpers.add_middleware import FlaskWithMiddleware as Flask
from ..routes import init_app
import sys
import os
from datetime import datetime, timezone
import signal

MAX_SCRIPT_STEPS = 7
SCAN_FILE = "/scan/status.txt"


def create_app():
    app = Flask(__name__, static_folder="../static")
    app.config.from_prefixed_env()
    app._INT_SCAN_FINISHED = False
    if "SCAN_FILE" not in app.config:
        app.config["SCAN_FILE"] = SCAN_FILE
    app.config["SCAN_DATE"] = "unknown date"

    def is_scan_finished():
        if app._INT_SCAN_FINISHED:
            return True
        with open(app.config["SCAN_FILE"], "r") as f:
            if "__END_OF_SCAN_SCRIPT__" in f.read():
                if os.getenv('DEBUG_SKIP_SCAN', '') != 'true':
                    app.config["SCAN_DATE"] = datetime.now(timezone.utc).strftime("%Y-%m-%d at %H:%M (UTC)")

                app._INT_SCAN_FINISHED = True
                return True
        return False

    @app.after_request
    def add_CORS_header(response):
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type"
        return response

    @app.route("/<path:path>", methods=["OPTIONS"])
    def allow_OPTION_CORS(path):
        return "OK", 200

    # bypass fail_scan middleware because it's before
    @app.route("/api/scan/status")
    def loading():
        with open(app.config["SCAN_FILE"], "r") as f:
            text = f.read()
            if "__END_OF_SCAN_SCRIPT__" in text:
                return {
                    "status": "done",
                    "maxsteps": MAX_SCRIPT_STEPS,
                    "step": MAX_SCRIPT_STEPS,
                    "message": "Scan complete"
                }
            else:
                step = text.splitlines()[-1].split(" ")
                return {
                    "status": "running",
                    "maxsteps": MAX_SCRIPT_STEPS,
                    "step": int(step.pop(0)),
                    "message": " ".join(step)
                }

    @app.middleware("/api")
    def fail_scan_not_finished(*args, **kw):
        if not is_scan_finished():
            return {"error": "Scan not finished"}, 503

    init_app(app)
    return app


def stop_handler(signal, frame):
    print("Stopping Flask server")
    sys.exit(0)


signal.signal(signal.SIGINT, stop_handler)
