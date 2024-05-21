# -*- coding: utf-8 -*-
import pytest
from src.models.cvss import CVSS


@pytest.fixture
def cvss_critical():
    return CVSS("3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "nist-cve-2024-3658-wordpress",
                9.8, 3.9, 5.9)


@pytest.fixture
def cvss_high():
    return CVSS("3.1", "CVSS:3.1/AV:A/AC:L/PR:H/UI:R/S:C/C:H/I:H/A:H", "nist-cve-2024-29000-solarwind",
                7.6, 1.2, 6.0)


@pytest.fixture
def cvss_medium():
    return CVSS("3.1", "CVSS:3.1/AV:L/AC:M/PR:L/UI:R/S:U/C:L/I:L/A:L", "fake-cve-1",
                5.4, 1.2, 4.0)


@pytest.fixture
def cvss_low():
    return CVSS("3.1", "CVSS:3.1/AV:P/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:N", "fake-cve-2",
                2.8, 1.0, 2.0)


@pytest.fixture
def cvss_invalid():
    return CVSS("x.x", "CVSS:x.x/AV:Z/AC:Z/PR:Z/UI:Z/S:Z/C:Z/I:Z/A:Z/Au:Z", "fake-cve-z",
                0.0, 0.0, 0.0)


def test_bunch_cvss_3_1(cvss_critical, cvss_high, cvss_medium, cvss_low):
    """
    GIVEN a bunch of CVSS 3.1 score
    WHEN getting severity and long descriptions
    THEN check the CVSS severity and parsing of vector string is correct
    """
    assert cvss_critical.severity() == "Critical"
    assert cvss_high.severity() == "High"
    assert cvss_medium.severity() == "Medium"
    assert cvss_low.severity() == "Low"

    assert cvss_critical.attack_vector_long == "Network"
    assert cvss_high.attack_vector_long == "Adjacent Network"
    assert cvss_medium.attack_vector_long == "Local"
    assert cvss_low.attack_vector_long == "Physical"

    assert cvss_critical.attack_complexity_long == "Low"
    assert cvss_medium.attack_complexity_long == "Medium"
    assert cvss_low.attack_complexity_long == "High"

    assert cvss_critical.privileges_required_long == "None"
    assert cvss_high.privileges_required_long == "High"
    assert cvss_medium.privileges_required_long == "Low"

    assert cvss_critical.user_interaction_long == "None"
    assert cvss_high.user_interaction_long == "Required"
    assert cvss_medium.user_interaction_long == "Required"

    assert cvss_critical.scope_long == "Unchanged"
    assert cvss_high.scope_long == "Changed"

    assert cvss_critical.confidentiality_impact_long == "High"
    assert cvss_medium.confidentiality_impact_long == "Low"
    assert cvss_low.confidentiality_impact_long == "None"

    assert cvss_critical.integrity_impact_long == "High"
    assert cvss_medium.integrity_impact_long == "Low"
    assert cvss_low.integrity_impact_long == "None"

    assert cvss_critical.availability_impact_long == "High"
    assert cvss_medium.availability_impact_long == "Low"
    assert cvss_low.availability_impact_long == "None"


def test_invalid_cvss(cvss_invalid):
    """
    GIVEN a invalid CVSS score
    WHEN creating a CVSS object
    THEN check the CVSS severity and parsing of vector string is correct
    """
    assert cvss_invalid.severity() == "Low"
    assert cvss_invalid.scope_long == "Unknown"
    assert cvss_invalid.attack_vector_long == "Unknown"
    assert cvss_invalid.authentication_long == "Unknown"
    assert cvss_invalid.user_interaction_long == "Unknown"
    assert cvss_invalid.integrity_impact_long == "Unknown"
    assert cvss_invalid.attack_complexity_long == "Unknown"
    assert cvss_invalid.privileges_required_long == "Unknown"
    assert cvss_invalid.availability_impact_long == "Unknown"
    assert cvss_invalid.confidentiality_impact_long == "Unknown"


def test_vector_string_2():
    """
    GIVEN a CVSS 2.0 score
    WHEN creating a CVSS object
    THEN check the CVSS severity and parsing of vector string is correct
    """
    cvss = CVSS("2.0", "AV:N/AC:L/Au:N/C:N/I:N/A:N", "old", 9.8, 5.0, 7.0)
    assert cvss.authentication_long == "None"
    assert cvss.confidentiality_impact_long == "None"
    assert cvss.integrity_impact_long == "None"
    assert cvss.availability_impact_long == "None"

    cvss = CVSS("2.0", "AV:N/AC:L/Au:S/C:P/I:P/A:P", "old", 7.3, 5.0, 7.0)
    assert cvss.authentication_long == "Single"
    assert cvss.confidentiality_impact_long == "Partial"
    assert cvss.integrity_impact_long == "Partial"
    assert cvss.availability_impact_long == "Partial"

    cvss = CVSS("2.0", "AV:A/AC:L/Au:M/C:C/I:C/A:C", "old", 5.0, 2.0, 4.0)
    assert cvss.authentication_long == "Multiple"
    assert cvss.confidentiality_impact_long == "Complete"
    assert cvss.integrity_impact_long == "Complete"
    assert cvss.availability_impact_long == "Complete"


def test_export_import_cvss(cvss_critical):
    """
    GIVEN a CVSS object
    WHEN exporting to dict and importing back from this dict
    THEN check the CVSS is the same
    """
    cvss2 = CVSS.from_dict(cvss_critical.to_dict())
    assert cvss_critical == cvss2
    assert hash(cvss_critical) == hash(cvss2)
    assert cvss_critical.version == cvss2.version
    assert cvss_critical.severity() == cvss2.severity()
    assert cvss_critical.vector_string == cvss2.vector_string


def test_compare_cvss(cvss_critical, cvss_high):
    """
    GIVEN two different CVSS objects
    WHEN comparing the two CVSS
    THEN check the comparison is correct
    """
    assert cvss_critical != 42
    assert cvss_critical != cvss_high
    assert str(cvss_critical) != str(cvss_high)
    assert hash(cvss_critical) != hash(cvss_high)
