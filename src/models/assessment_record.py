# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
#
# Backward-compatibility shim.  All code should import from
# ``src.models.assessment`` directly.

from .assessment import (  # noqa: F401
    Assessment,
    VALID_STATUS_OPENVEX,
    VALID_STATUS_CDX_VEX,
    STATUS_CDX_VEX_TO_OPENVEX,
    STATUS_OPENVEX_TO_CDX_VEX,
    VALID_JUSTIFICATION_OPENVEX,
    VALID_JUSTIFICATION_CDX_VEX,
    JUSTIFICATION_CDX_VEX_TO_OPENVEX,
    JUSTIFICATION_OPENVEX_TO_CDX_VEX,
    RESPONSES_CDX_VEX,
)
