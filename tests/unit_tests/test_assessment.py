# -*- coding: utf-8 -*-
import pytest
from src.models.package import Package
from src.models.assessment import VulnAssessment


@pytest.fixture
def pkg_ABC():
    pkg = Package("abc", "1.0.0")
    pkg.generate_generic_cpe()
    pkg.generate_generic_purl()
    return pkg


@pytest.fixture
def pkg_XYZ():
    pkg = Package("xyz", "2.3.4")
    pkg.generate_generic_cpe()
    pkg.generate_generic_purl()
    return pkg


@pytest.fixture
def assessment_initial(pkg_ABC):
    assessment = VulnAssessment("CVE-456", [pkg_ABC])
    assessment.set_status("in_triage")
    assessment.set_status_notes("Initial assessment")
    assessment.add_package("inexistant_package@0.0.1")
    return assessment


@pytest.fixture
def assessment_active(pkg_ABC):
    assessment = VulnAssessment("CVE-456", [pkg_ABC])
    assessment.set_status("exploitable")
    assessment.set_status_notes("package ABC is vulnerable to CVE-456", True)
    assessment.set_status_notes("package ABC is vulnerable to CVE-123", True)
    assessment.set_workaround("disables feature X by setting environment variable Y")
    assessment.add_response("workaround_available")
    return assessment


@pytest.fixture
def assessment_fixed(pkg_ABC):
    assessment = VulnAssessment("CVE-456", [pkg_ABC])
    assessment.set_status("fixed")
    assessment.set_status_notes("package ABC in versions >= 1.4.0 is no longer vulnerable to CVE-456")
    assessment.add_response("update")
    return assessment


@pytest.fixture
def assessment_not_affected(pkg_XYZ):
    assessment = VulnAssessment("CVE-789", [pkg_XYZ])
    assessment.set_status("not_affected")
    assessment.set_status_notes("package XYZ is not affected by CVE-789")
    assessment.set_justification("code_not_present")
    assessment.set_not_affected_reason("package XYZ does not contain the vulnerable code")
    return assessment


def test_export_as_openvex(assessment_initial, assessment_active, assessment_fixed, assessment_not_affected):
    """
    GIVEN assessments with different statuses set in cdx or openvex format
    WHEN exporting as openVEX
    THEN primary data should be exported correctly
    """
    assert {
        "vulnerability": {"name": "CVE-456"},
        "status": "under_investigation",
        "status_notes": "Initial assessment",
    }.items() <= assessment_initial.to_openvex_dict().items()

    assert {
        "vulnerability": {"name": "CVE-456"},
        "status": "affected",
        "status_notes": "package ABC is vulnerable to CVE-456\npackage ABC is vulnerable to CVE-123",
        "action_statement": "disables feature X by setting environment variable Y",
    }.items() <= assessment_active.to_openvex_dict().items()

    assert {
        "vulnerability": {"name": "CVE-456"},
        "status": "fixed",
        "status_notes": "package ABC in versions >= 1.4.0 is no longer vulnerable to CVE-456",
    }.items() <= assessment_fixed.to_openvex_dict().items()

    assert {
        "vulnerability": {"name": "CVE-789"},
        "status": "not_affected",
        "status_notes": "package XYZ is not affected by CVE-789",
        "justification": "vulnerable_code_not_present",
        "impact_statement": "package XYZ does not contain the vulnerable code",
    }.items() <= assessment_not_affected.to_openvex_dict().items()


def test_export_as_cdx(assessment_initial, assessment_active, assessment_fixed, assessment_not_affected):
    """
    GIVEN assessments with different statuses set in cdx or openvex format
    WHEN exporting as Cyclone VEX
    THEN primary data should be exported correctly
    """
    assert {
        "state": "in_triage",
        "details": "Initial assessment",
    }.items() <= assessment_initial.to_cdx_vex_dict()['analysis'].items()

    assert {
        "state": "exploitable",
        "details": "package ABC is vulnerable to CVE-456\npackage ABC is vulnerable to CVE-123",
        "response": ["workaround_available"],
    }.items() <= assessment_active.to_cdx_vex_dict()['analysis'].items()

    assert {
        "state": "resolved",
        "details": "package ABC in versions >= 1.4.0 is no longer vulnerable to CVE-456",
        "response": ["update"],
    }.items() <= assessment_fixed.to_cdx_vex_dict()['analysis'].items()

    assert {
        "state": "not_affected",
        "details": "package XYZ is not affected by CVE-789",
        "justification": "code_not_present",
    }.items() <= assessment_not_affected.to_cdx_vex_dict()['analysis'].items()


def test_compatible_status(assessment_initial, assessment_active, assessment_fixed, assessment_not_affected):
    """
    GIVEN assessments with different statuses set in cdx or openvex format
    WHEN converting to one or the other format
    THEN conversion should be accurate and working
    """
    assert assessment_initial.is_compatible_status("in_triage")
    assert assessment_initial.is_compatible_status("under_investigation")
    assert not assessment_initial.is_compatible_status("affected")
    assert not assessment_initial.is_compatible_status("fixed")
    assert not assessment_initial.is_compatible_status("not_affected")

    assert not assessment_active.is_compatible_status("in_triage")
    assert assessment_active.is_compatible_status("affected")
    assert assessment_active.is_compatible_status("exploitable")
    assert not assessment_active.is_compatible_status("fixed")
    assert not assessment_active.is_compatible_status("not_affected")

    assert not assessment_fixed.is_compatible_status("in_triage")
    assert not assessment_fixed.is_compatible_status("affected")
    assert assessment_fixed.is_compatible_status("fixed")
    assert assessment_fixed.is_compatible_status("resolved")
    assert not assessment_fixed.is_compatible_status("not_affected")

    assert not assessment_not_affected.is_compatible_status("in_triage")
    assert not assessment_not_affected.is_compatible_status("affected")
    assert not assessment_not_affected.is_compatible_status("fixed")
    assert assessment_not_affected.is_compatible_status("not_affected")


def test_compatible_justification(assessment_initial, assessment_active, assessment_fixed, assessment_not_affected):
    """
    GIVEN assessments with differents justifications set in cdx or openvex format
    WHEN converting from one format to another
    THEN conversion should be accurate
    """
    assert assessment_active.is_justification_required() is False
    assert assessment_fixed.is_justification_required() is False
    assert assessment_initial.is_justification_required() is False
    assert assessment_not_affected.is_justification_required() is True

    assert assessment_not_affected.set_justification("code_not_present") is True
    assert assessment_not_affected.is_compatible_justification("vulnerable_code_not_present") is True
    assert assessment_not_affected.is_compatible_justification("code_not_present") is True
    assert assessment_not_affected.is_compatible_justification("inline_mitigations_already_exist") is False
    assert assessment_not_affected.get_justification_openvex() == "vulnerable_code_not_present"
    assert assessment_not_affected.get_justification_cdx_vex() == "code_not_present"

    assert assessment_not_affected.set_justification("inline_mitigations_already_exist") is True
    assert assessment_not_affected.is_compatible_justification("protected_by_mitigating_control") is True
    assert assessment_not_affected.is_compatible_justification("inline_mitigations_already_exist") is True
    assert assessment_not_affected.is_compatible_justification("code_not_present") is False
    assert assessment_not_affected.get_justification_openvex() == "inline_mitigations_already_exist"
    assert assessment_not_affected.get_justification_cdx_vex() == "protected_by_mitigating_control"


def test_response_items(assessment_active):
    """
    GIVEN an assessment instance
    WHEN adding, removing and handling responses elements
    THEN response should not be duplicated and processed corectly
    """
    assert assessment_active.remove_response("workaround_available") is True
    assert assessment_active.remove_response("workaround_available") is False
    assessment_active.set_workaround("will_not_fix")

    assert assessment_active.to_cdx_vex_dict()['analysis']['response'] == ["will_not_fix"]
    assessment_active.responses = []
    assessment_active.set_workaround("some text about a workaround")
    assert assessment_active.to_cdx_vex_dict()['analysis']['response'] == ["workaround_available"]


def test_invalid_inputs(assessment_initial, assessment_not_affected):
    """
    GIVEN an assessment instance
    WHEN trying to set invalid status, justification, or call invalid methods
    THEN mehtods must handle invalid inputs and return False instead of error
    """
    assert assessment_not_affected.set_status("invalid_status") is False
    assert assessment_not_affected.add_package(None) is False
    assert assessment_not_affected.add_response("invalid_response") is False
    assert assessment_not_affected.remove_response("invalid_response") is False
    assert assessment_initial.get_justification_cdx_vex() is None
    assert assessment_initial.get_justification_openvex() is None
    assert assessment_initial.set_justification("invalid_justification") is False
    assert assessment_initial.is_compatible_justification("invalid_justification") is False

    assessment_initial.status = "invalid_status"
    assert assessment_initial.to_openvex_dict() is None
    assert assessment_initial.to_cdx_vex_dict() is None

    assessment_not_affected.justification = "invalid_justification"
    assessment_not_affected.impact_statement = ""
    assert assessment_not_affected.to_openvex_dict() is None        # justification MUST be given
    assert assessment_not_affected.to_cdx_vex_dict() is not None    # justification SHOULD be given


def test_export_import_assessment(assessment_not_affected):
    """
    GIVEN an assessment instance
    WHEN exporting to dict and importing back to a new assessment
    THEN data should remain the same (except id)
    """
    new_assessment = VulnAssessment.from_dict(assessment_not_affected.to_dict())
    assert new_assessment.to_dict().items() == assessment_not_affected.to_dict().items()
    assert new_assessment.vuln_id == assessment_not_affected.vuln_id
    assert new_assessment.packages == assessment_not_affected.packages
    assert new_assessment.status == assessment_not_affected.status
    assert new_assessment.status_notes == assessment_not_affected.status_notes
    assert new_assessment.responses == assessment_not_affected.responses
    assert new_assessment.justification == assessment_not_affected.justification
    assert new_assessment.impact_statement == assessment_not_affected.impact_statement
    assert new_assessment.workaround == assessment_not_affected.workaround
    assert new_assessment.timestamp == assessment_not_affected.timestamp
    assert new_assessment.last_update == assessment_not_affected.last_update
    assert new_assessment.workaround_timestamp == assessment_not_affected.workaround_timestamp


def test_specific_handling_false_positive():
    """
    GIVEN a vulnerability with false_positive status
    WHEN converting to OpenVEX
    THEN convert to the equivalent 'not_affected' + 'component_not_present' status
    """
    from_cdx = VulnAssessment("CVE-000", [])
    from_cdx.set_status("false_positive")
    from_cdx.set_justification("code_not_present")

    assert {
        "status": "not_affected",
        "justification": "component_not_present",
    }.items() <= from_cdx.to_openvex_dict().items()

    from_openvex = VulnAssessment("CVE-000", [])
    from_openvex.set_status("not_affected")
    from_openvex.set_justification("component_not_present")

    assert {
        "state": "false_positive",
    }.items() <= from_openvex.to_cdx_vex_dict()['analysis'].items()


def test_merge_assessments(assessment_initial, assessment_active, assessment_fixed, assessment_not_affected):
    """
    GIVEN assessments with different informations
    WHEN merging assessments together
    THEN merged assessment should have the most recent status w/o losing information
    """
    # setup
    assessment_fixed.set_workaround("update to >= 7.10.0")
    assessment_not_affected.set_workaround("this is a useless workaround")
    assessment_initial.set_not_affected_reason("some text which make non-sense")

    # ensure merge fail if ids are different
    assert assessment_active.merge(assessment_fixed) is False
    assessment_fixed.id = assessment_active.id
    assessment_not_affected.id = assessment_initial.id
    assert assessment_active.merge(assessment_fixed) is True

    # ensure merge fail if vuln_id are different
    assert assessment_initial.merge(assessment_not_affected) is False
    assessment_not_affected.vuln_id = "CVE-456"
    assert assessment_initial.merge(assessment_not_affected) is True

    assert {
        "status": "fixed",
        "status_notes": "package ABC is vulnerable to CVE-456\n"
                        + "package ABC is vulnerable to CVE-123\n"
                        + "package ABC in versions >= 1.4.0 is no longer vulnerable to CVE-456",
        "responses": ["workaround_available", "update"],
        "workaround": "update to >= 7.10.0",
    }.items() <= assessment_active.to_dict().items()

    assert {
        "status": "not_affected",
        "status_notes": "Initial assessment\n"
                        + "package XYZ is not affected by CVE-789",
        "justification": "code_not_present",
        "impact_statement": "some text which make non-sense\npackage XYZ does not contain the vulnerable code",
        "responses": [],
        "workaround": "this is a useless workaround",
    }.items() <= assessment_initial.to_dict().items()
