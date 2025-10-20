# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from ..controllers.nvd_db import NVD_DB
import os
import glob
import lzma
import shutil

def decompress_nvd_db(nvd_db_path):
    db_dir, db_name = os.path.dirname(nvd_db_path), os.path.basename(nvd_db_path)
    matches = sorted(glob.glob(f"{db_dir}/{db_name}.*.xz"), key=os.path.getmtime, reverse=True) # Get the most recent xz file
    
    # With no marches, we exit the function and build the DB from scratch in the next step
    if not matches:
        return
    
    src = matches[0] # Take the most recent file
    
    try:
        with lzma.open(src, 'rb') as f_in, open(nvd_db_path, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)
        os.remove(src)
    except:
        if os.path.exists(nvd_db_path):
            os.remove(nvd_db_path)
        raise

def fetch_db_updates():
    nvd_db_path = os.getenv("NVD_DB_PATH", "/cache/vulnscout/nvd.db")
    
    # Check for and decompress any compressed database files first
    decompress_nvd_db(nvd_db_path)
    
    # Contrinue with syncing, either from scratch or from the decompressed DB last entry
    nvd_db = NVD_DB(nvd_db_path)
    nvd_api_key = os.getenv("NVD_API_KEY")
    if not nvd_api_key:
        print("NVD API key not found, this may slow down db update. See NVD_API_KEY configuration")
    else:
        nvd_db.nvd_api_key = nvd_api_key
    nvd_db.set_writing_flag(True)
    for step, total in nvd_db.build_initial_db():
        print(f"NVD update: {step} / {total} [{round((step / total) * 100)}%]", flush=True)
    for txt in nvd_db.update_db():
        print(f"NVD update: {txt}", flush=True)
    nvd_db.in_sync = True
    nvd_db.set_writing_flag(False)


if __name__ == "__main__":
    fetch_db_updates()
    print("DB is now synced")
