# -*- coding: utf-8 -*-
#
# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Unit tests for the fuzzy version comparison helper used by copy-assessments."""

import pytest

from src.helpers.version_match import (
    versions_match,
    _parse_components,
    _semver_components,
    _split_components,
)


class TestVersionsMatchPrecisionOne:
    """precision=1 → only the major component must match."""

    def test_same_major_different_minor_matches(self):
        assert versions_match("6.5", "6.7", 1) is True

    def test_different_major_does_not_match(self):
        assert versions_match("6.5", "7.0", 1) is False

    def test_major_only_versions(self):
        assert versions_match("2", "2.0.0", 1) is True

    def test_different_major_full_versions(self):
        assert versions_match("1.1.1", "3.0.0", 1) is False


class TestVersionsMatchPrecisionTwo:
    """precision=2 → major AND minor must match."""

    def test_same_major_minor_different_patch_matches(self):
        assert versions_match("6.5.1", "6.5.9", 2) is True

    def test_same_major_different_minor_does_not_match(self):
        assert versions_match("6.5", "6.7", 2) is False

    def test_same_major_minor_matches(self):
        assert versions_match("10.2.3", "10.2.99", 2) is True


class TestVersionsMatchEdgeCases:
    def test_both_none_treated_as_zero(self):
        assert versions_match(None, None, 1) is True

    def test_empty_versus_nonzero(self):
        assert versions_match("", "1.0", 1) is False

    def test_none_versus_zero_major(self):
        assert versions_match(None, "0.5", 1) is True

    def test_precision_zero_always_matches(self):
        assert versions_match("6.5", "9.9", 0) is True

    def test_negative_precision_always_matches(self):
        assert versions_match("6.5", "9.9", -1) is True

    def test_precision_beyond_available_components_pads_with_zero(self):
        # "6" → (6, 0, 0); "6.0.0" → (6, 0, 0); equal up to precision 3
        assert versions_match("6", "6.0.0", 3) is True

    def test_precision_beyond_components_detects_difference(self):
        # "6" → (6, 0, 0); "6.1" → (6, 1, 0) differ at index 1
        assert versions_match("6", "6.1", 2) is False


class TestVersionsMatchNonSemver:
    """Versions that are not valid semver fall back to integer-prefix splitting."""

    def test_openssl_style_suffix_matches(self):
        assert versions_match("1.1.1w", "1.1.1k", 3) is True

    def test_openssl_style_suffix_differs_on_patch(self):
        assert versions_match("1.1.1w", "1.1.2k", 3) is False

    def test_build_metadata_is_stripped(self):
        assert versions_match("2.4.1+deb10", "2.4.1-1ubuntu", 3) is True

    def test_non_semver_full_mismatch(self):
        assert versions_match("1.2.3", "1.2.4", 3) is False


class TestParseComponents:
    def test_semver_path(self):
        assert _parse_components("6.5.1") == (6, 5, 1)

    def test_semver_optional_minor_patch(self):
        assert _parse_components("6.5") == (6, 5, 0)

    def test_empty_returns_zero(self):
        assert _parse_components("") == (0,)

    def test_non_numeric_returns_zero(self):
        assert _parse_components("abc") == (0,)

    def test_fallback_split_for_suffix(self):
        assert _parse_components("1.1.1w") == (1, 1, 1)


class TestSemverComponents:
    def test_full_semver(self):
        assert _semver_components("1.2.3") == (1, 2, 3)

    def test_optional_minor_patch(self):
        assert _semver_components("4") == (4, 0, 0)

    def test_invalid_raises_value_error(self):
        with pytest.raises(ValueError):
            _semver_components("1.1.1w")


class TestSplitComponents:
    def test_plain_dotted(self):
        assert _split_components("1.2.3") == (1, 2, 3)

    def test_stops_at_non_numeric_segment(self):
        assert _split_components("1.2.beta") == (1, 2)

    def test_strips_prerelease_and_build(self):
        assert _split_components("1.2.3-rc1+build") == (1, 2, 3)

    def test_leading_non_numeric_returns_empty(self):
        assert _split_components("abc.def") == ()
