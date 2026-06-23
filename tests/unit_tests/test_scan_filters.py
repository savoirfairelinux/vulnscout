# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for the scanner input filters (kernel companion package exclusion)."""

from dataclasses import dataclass

from src.helpers.scan_filters import (
    is_kernel_package_name,
    filter_scannable_packages,
)


@dataclass
class _FakePkg:
    name: str


class TestIsKernelPackageName:
    def test_kernel_module_prefix(self):
        assert is_kernel_package_name("kernel-module-foo") is True

    def test_kernel_modules_meta(self):
        assert is_kernel_package_name("kernel-modules") is True

    def test_kernel_versioned_meta(self):
        assert is_kernel_package_name("kernel-6.6.116") is True

    def test_kernel_devicetree(self):
        assert is_kernel_package_name("kernel-devicetree") is True

    def test_kernel_image(self):
        assert is_kernel_package_name("kernel-image-6.6.116") is True

    def test_case_insensitive(self):
        assert is_kernel_package_name("Kernel-Module-Bar") is True

    def test_leading_whitespace(self):
        assert is_kernel_package_name("  kernel-module-baz") is True

    def test_regular_package(self):
        assert is_kernel_package_name("openssl") is False

    def test_real_kernel_recipe_kept(self):
        # The actual kernel recipe (``linux-*``) carries the real kernel CVEs
        # and must remain scannable.
        assert is_kernel_package_name("linux-stm32mp") is False

    def test_unrelated_kernel_prefix_kept(self):
        # No hyphen after "kernel" -> not a kernel companion package.
        assert is_kernel_package_name("kernelshark") is False

    def test_bare_kernel_kept(self):
        assert is_kernel_package_name("kernel") is False

    def test_none(self):
        assert is_kernel_package_name(None) is False

    def test_empty(self):
        assert is_kernel_package_name("") is False


class TestFilterScannablePackages:
    def test_drops_kernel_packages(self):
        pkgs = [
            _FakePkg("openssl"),
            _FakePkg("kernel-module-usbcore"),
            _FakePkg("kernel-6.6.116"),
            _FakePkg("kernel-devicetree"),
            _FakePkg("requests"),
        ]
        result = filter_scannable_packages(pkgs)
        assert [p.name for p in result] == ["openssl", "requests"]

    def test_keeps_all_when_no_kernel_packages(self):
        pkgs = [_FakePkg("openssl"), _FakePkg("requests")]
        assert filter_scannable_packages(pkgs) == pkgs

    def test_empty_list(self):
        assert filter_scannable_packages([]) == []
