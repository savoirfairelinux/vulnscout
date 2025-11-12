# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from ..controllers.nvd_db import NVD_DB
from ..helpers.nvd_logging import setup_logging, log_and_print
import os
import glob
import lzma
import shutil


def decompress_nvd_db(nvd_db_path, verbose_logging=True):
    db_dir, db_name = os.path.dirname(nvd_db_path), os.path.basename(nvd_db_path)
    matches = sorted(glob.glob(f"{db_dir}/{db_name}.*.xz"), key=os.path.getmtime, reverse=True)
    if not matches:
        log_and_print("No compressed database files found", verbose_logging)
        return
    src = matches[0]
    log_and_print(f"Decompressing database from {src}", verbose_logging)
    try:
        with lzma.open(src, "rb") as f_in, open(nvd_db_path, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)
        os.remove(src)
        log_and_print(f"Successfully decompressed database to {nvd_db_path}", verbose_logging)
    except Exception as e:
        log_and_print(f"Error decompressing database: {e}", verbose_logging, force_print=True)
        if os.path.exists(nvd_db_path):
            os.remove(nvd_db_path)
        raise


def fetch_db_updates():
    verbose_logging = setup_logging()
    nvd_db_path = os.getenv("NVD_DB_PATH", "/cache/vulnscout/nvd.db")
    log_and_print("Starting NVD database update", verbose_logging)
    if not verbose_logging:
        log_and_print("NVD DB is syncing, it may take a few minutes", verbose_logging=False, force_print=True)
    decompress_nvd_db(nvd_db_path, verbose_logging)
    log_and_print("Initializing NVD database connection", verbose_logging)
    nvd_db = NVD_DB(nvd_db_path)
    nvd_api_key = os.getenv("NVD_API_KEY")
    if not nvd_api_key:
        log_and_print(
            "NVD API key not found, this may slow down db update. See NVD_API_KEY configuration",
            verbose_logging
        )
    else:
        log_and_print("NVD API key found, using authenticated requests", verbose_logging)
        nvd_db.nvd_api_key = nvd_api_key
    nvd_db.set_writing_flag(True)
    for step, total in nvd_db.build_initial_db():
        percent = round((step / total) * 100) if total else 100
        message = f"NVD update: {step} / {total} [{percent}%]"
        log_and_print(message, verbose_logging)
    for txt in nvd_db.update_db():
        message = f"NVD update: {txt}"
        log_and_print(message, verbose_logging)
    nvd_db.in_sync = True
    nvd_db.set_writing_flag(False)
    log_and_print("NVD DB sync completed successfully", verbose_logging, force_print=True)


if __name__ == "__main__":
    try:
        fetch_db_updates()
    except Exception as e:
        verbose_logging = os.getenv("NVD_VERBOSE_LOGGING", "false").lower() == "true"
        error_msg = f"Error during NVD database update: {e}"
        log_and_print(error_msg, verbose_logging, force_print=True)
        raise
