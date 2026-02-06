# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from ..controllers.nvd_db import NVD_DB
from ..controllers.nvd_progress import NVDProgressTracker
import os


def fetch_db_updates():
    nvd_db_path = os.getenv("NVD_DB_PATH", "/cache/vulnscout/nvd.db")
    nvd_db = NVD_DB(nvd_db_path)
    nvd_api_key = os.getenv("NVD_API_KEY")
    progress_tracker = NVDProgressTracker()

    if not nvd_api_key:
        print("NVD API key not found, this may slow down db update. See NVD_API_KEY configuration")
    else:
        nvd_db.nvd_api_key = nvd_api_key

    try:
        nvd_db.set_writing_flag(True)

        # Initial DB build phase
        progress_tracker.start("initial_build")
        for step, total in nvd_db.build_initial_db():
            percentage = round((step / total) * 100)
            message = f"NVD update: {step} / {total} [{percentage}%]"
            print(message, flush=True)
            progress_tracker.update("initial_build", step, total, message)

        progress_tracker.update("incremental_update", 0, 1, "Starting incremental update")
        for txt in nvd_db.update_db():
            message = f"NVD update: {txt}"
            print(message, flush=True)
            progress_tracker.update("incremental_update", 0, 1, message)

        nvd_db.in_sync = True
        nvd_db.set_writing_flag(False)
        progress_tracker.complete()
    except Exception as e:
        progress_tracker.error(f"Error during NVD update: {str(e)}")
        raise


if __name__ == "__main__":
    fetch_db_updates()
    print("DB is now synced")
