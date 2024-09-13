# -*- coding: utf-8 -*-
from ..controllers.nvd_db import NVD_DB
import os


def fetch_db_updates():
    nvd_db_path = os.getenv("NVD_DB_PATH", "/cache/vulnscout/nvd.db")
    nvd_db = NVD_DB(nvd_db_path)
    nvd_db.nvd_api_key = os.getenv("NVD_API_KEY")
    if not nvd_db.nvd_api_key:
        print("NVD API key not found, this may slow down db update. See NVD_API_KEY configuration")
    for step, total in nvd_db.build_initial_db():
        print(f"NVD update: {step} / {total} [{round((step / total) * 100)}%]", flush=True)
    for txt in nvd_db.update_db():
        print(f"NVD update: {txt}", flush=True)
    nvd_db.in_sync = True


if __name__ == "__main__":
    fetch_db_updates()
    print("DB is now synced")
