# -*- coding: utf-8 -*-
#
# Copyright (C) 2025 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import os
from ..controllers.epss_db import EPSS_DB


def fetch_epss_updates():
    epss_db_path = os.getenv("EPSS_DB_PATH", "/cache/vulnscout/epss.db")
    epss_db = EPSS_DB(epss_db_path)

    if epss_db.needs_update():
        print(f"EPSS DB outdated or missing: updating now...", flush=True)
        epss_db.update_epss()
        print("EPSS DB update complete!", flush=True)
    else:
        print("EPSS DB is up to date, skipping synccing", flush=True)
        
if __name__ == "__main__":
    fetch_epss_updates()
    print("EPSS DB is now synced")
