# -*- coding: utf-8 -*-
import pytest
from src.helpers.fixs_scrapper import FixsScrapper
from src.models.vulnerability import Vulnerability
import json


@pytest.fixture
def ex_nvd_simple():
    # CVE-2003-0063
    return json.loads("""{ "cve": {
        "configurations": [
            {"nodes": [
                {
                    "operator": "OR",
                    "negate": false,
                    "cpeMatch": [
                        {
                            "vulnerable": true,
                            "criteria": "cpe:2.3:a:xfree86_project:x11r6:4.0:*:*:*:*:*:*:*"
                        },
                        {
                            "vulnerable": true,
                            "criteria": "cpe:2.3:a:xfree86_project:x11r6:4.0.1:*:*:*:*:*:*:*"
                        },
                        {
                            "vulnerable": true,
                            "criteria": "cpe:2.3:a:xfree86_project:x11r6:4.2.1:*:*:*:*:*:*:*"
                        }
                    ]
                }
            ]}
        ]
    } }""")


@pytest.fixture
def ex_nvd_start_end():
    # CVE-2022-29847
    return json.loads("""{ "cve": {
        "configurations": [
            {"nodes": [
                {
                    "operator": "OR",
                    "negate": false,
                    "cpeMatch": [
                        {
                            "vulnerable": true,
                            "criteria": "cpe:2.3:a:progress:whatsup_gold:*:*:*:*:*:*:*:*",
                            "versionStartIncluding": "21.0.0",
                            "versionEndIncluding": "21.1.1"
                        },
                        {
                            "vulnerable": true,
                            "criteria": "cpe:2.3:a:progress:whatsup_gold:22.0.0:*:*:*:*:*:*:*"
                        },
                        {
                            "vulnerable": false,
                            "criteria": "cpe:2.3:a:progress:whatsup_gold:22.2.0:*:*:*:*:*:*:*"
                        },
                        {
                            "vulnerable": true,
                            "criteria": "cpe:2.3:a:progress:whatsup_gold:*:*:*:*:*:*:*:*",
                            "versionStartExcluding": "123.1.0",
                            "versionEndExcluding": "123.3.0"
                        }
                    ]
                }
            ]}
        ]
    } }""")


@pytest.fixture
def ex_nvd_inversed():
    return json.loads("""{ "cve": {
        "configurations": [
            {"nodes": [
                {
                    "operator": "OR",
                    "negate": false,
                    "cpeMatch": [
                        {
                            "vulnerable": false,
                            "criteria": "cpe:2.3:a:*:abc:*:*:*:*:*:*:*:*",
                            "versionStartExcluding": "1.1.0",
                            "versionEndExcluding": "1.3.0"
                        }
                    ]
                },
                {
                    "operator": "OR",
                    "negate": true,
                    "cpeMatch": [
                        {
                            "vulnerable": true,
                            "criteria": "cpe:2.3:a:*:abc:*:*:*:*:*:*:*:*",
                            "versionStartIncluding": "2.0.0",
                            "versionEndIncluding": "2.1.1"
                        }
                    ]
                }
            ]}
        ]
    } }""")


@pytest.fixture
def ex_nvd_not_cpe():
    return json.loads("""{ "cve": {
        "configurations": [
            {"nodes": [
                {
                    "operator": "OR",
                    "negate": false,
                    "cpeMatch": [
                        {
                            "vulnerable": true,
                            "criteria": "some invalid value"
                        }
                    ]
                }
            ]}
        ]
    } }""")


def test_simple_nvd_scan(ex_nvd_simple):
    fxs = FixsScrapper()
    fxs.search_in_nvd(ex_nvd_simple)
    assert len(fxs.list_fixing_versions()) == 0
    assert len(fxs.list_vulnerables_versions()) == 3
    assert [
        "x11r6 = 4.0",
        "x11r6 = 4.0.1",
        "x11r6 = 4.2.1"
    ] == fxs.list_vulnerables_versions()


def test_start_end_nvd_scan(ex_nvd_start_end):
    fxs = FixsScrapper()
    fxs.search_in_nvd(ex_nvd_start_end)
    assert len(fxs.list_fixing_versions()) == 5
    assert [
        "whatsup_gold <=? 123.1.0",
        "whatsup_gold >=? 123.3.0",
        "whatsup_gold <? 21.0.0",
        "whatsup_gold >? 21.1.1",
        "whatsup_gold = 22.2.0"
    ] == fxs.list_fixing_versions()
    assert len(fxs.list_vulnerables_versions()) == 5
    assert [
        "whatsup_gold > 123.1.0",
        "whatsup_gold < 123.3.0",
        "whatsup_gold >= 21.0.0",
        "whatsup_gold <= 21.1.1",
        "whatsup_gold = 22.0.0"
    ] == fxs.list_vulnerables_versions()


def test_inversed_nvd_scan(ex_nvd_inversed):
    fxs = FixsScrapper()
    fxs.search_in_nvd(ex_nvd_inversed)
    assert len(fxs.list_fixing_versions()) == 4
    assert [
        "abc > 1.1.0",
        "abc < 1.3.0",
        "abc >= 2.0.0",
        "abc <= 2.1.1"
    ] == fxs.list_fixing_versions()
    assert len(fxs.list_vulnerables_versions()) == 4
    assert [
        "abc <=? 1.1.0",
        "abc >=? 1.3.0",
        "abc <? 2.0.0",
        "abc >? 2.1.1"
    ] == fxs.list_vulnerables_versions()


def test_not_cpe_nvd_scan(ex_nvd_not_cpe):
    fxs = FixsScrapper()
    fxs.search_in_nvd(ex_nvd_not_cpe)
    assert len(fxs.list_fixing_versions()) == 0
    assert len(fxs.list_vulnerables_versions()) == 0


def test_all_cve_scan(ex_nvd_simple, ex_nvd_start_end, ex_nvd_inversed, ex_nvd_not_cpe):
    fxs = FixsScrapper()
    fxs.search_in_nvd({
        "vulnerabilities": [
            ex_nvd_simple,
            ex_nvd_start_end,
            ex_nvd_inversed,
            ex_nvd_not_cpe
        ]
    })
    soluces = fxs.list_per_packages()
    assert len(soluces) == 3
    assert "whatsup_gold (nvd-cpe-match)" in soluces
    assert len(soluces["whatsup_gold (nvd-cpe-match)"]["fix"]) == 5
    assert len(soluces["x11r6 (nvd-cpe-match)"]["affected"]) == 3


def test_find_in_text():
    vuln = Vulnerability("CVE-0000-00000", "test", "demo", "demo")
    vuln.add_package("abc@1.0.0")
    vuln.add_text(
        "A security issue in main.c affecting version prior to 1.2.3 can lead to remote code execution",
        "test1"
    )
    vuln.add_text("All versions after 2.0 through 2.4.2 are affected", "test2")
    vuln.add_text("A temporary patch was released in version 3.2.7 and 3.3.2", "test3")
    fxs = FixsScrapper()
    fxs.search_in_vulnerability(vuln)

    assert len(fxs.list_fixing_versions()) == 5
    assert [
        "abc >=? 1.2.3",
        "abc <? 2.0",
        "abc >? 2.4.2",
        "abc ? 3.2.7",
        "abc ? 3.3.2"
    ] == fxs.list_fixing_versions()
    assert len(fxs.list_vulnerables_versions()) == 5
    assert [
        "abc <? 1.2.3",
        "abc >=? 2.0",
        "abc <=? 2.4.2",
        "abc ? 3.2.7",
        "abc ? 3.3.2"
    ] == fxs.list_vulnerables_versions()
