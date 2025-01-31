# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import pytest
from src.bin.spdx_merge import main
import os


@pytest.fixture
def setup(tmp_path):
    os.environ["INPUT_SPDX_FOLDER"] = "tests/spdx_merge/data"
    os.environ["OUTPUT_SPDX_FILE"] = str(tmp_path / "output.spdx.json")


def test_merge_files_default(setup):
    os.environ["IGNORE_PARSING_ERRORS"] = 'false'
    with pytest.raises(Exception):
        main()


def test_merge_files_with_ignore_errors(setup):
    os.environ["IGNORE_PARSING_ERRORS"] = 'true'
    main()
    with open(os.environ["OUTPUT_SPDX_FILE"], 'r') as f:
        data = f.read()
        assert "cairo" in data
        assert "1.16.0" in data
        assert "libssh" in data
        assert "0.8.9" in data
        assert "SPDX-2.3" in data
