from erislite.sweep.threat_sweep import (
    RISK_WEIGHTS,
    calculate_risk_score,
    contributes_detected_risk,
    inspection_coverage,
    prioritize_findings,
)


def _integrity_result(*tags):
    return {
        "status": "warning",
        "tags": list(tags),
        "details": ["Suspicious copy detected: /tmp/passwd.copy"],
    }


def test_suspicious_copy_contributes_risk():
    result = _integrity_result("suspicious_file_copy")

    assert inspection_coverage("integrity", result) == "complete"
    assert contributes_detected_risk("integrity", result)


def test_suspicious_copy_still_scores_during_partial_coverage():
    result = _integrity_result(
        "suspicious_file_copy",
        "integrity_scan_incomplete",
    )

    assert inspection_coverage("integrity", result) == "partial"
    assert contributes_detected_risk("integrity", result)

    score, breakdown, maximum = calculate_risk_score({"integrity": result})

    assert score == RISK_WEIGHTS["integrity"]
    assert breakdown["integrity"] == RISK_WEIGHTS["integrity"]
    assert maximum == RISK_WEIGHTS["integrity"]


def test_modified_file_and_copy_not_double_counted():
    result = _integrity_result(
        "file_integrity_issue",
        "suspicious_file_copy",
    )

    score, breakdown, maximum = calculate_risk_score({"integrity": result})

    assert score == RISK_WEIGHTS["integrity"]
    assert breakdown["integrity"] == RISK_WEIGHTS["integrity"]
    assert maximum == RISK_WEIGHTS["integrity"]


def test_suspicious_copy_appears_in_prioritized_findings():
    result = _integrity_result("suspicious_file_copy")

    findings = prioritize_findings({"integrity": result})

    assert len(findings) == 1
    assert findings[0]["module"] == "integrity"
    assert "suspicious_file_copy" in findings[0]["tags"]
    assert any("/tmp/passwd.copy" in detail for detail in findings[0]["details"])


def test_copy_scan_incomplete_without_detection_does_not_score():
    result = {
        "status": "error",
        "tags": ["integrity_scan_incomplete"],
        "details": ["Copy scan candidate limit reached"],
    }

    assert inspection_coverage("integrity", result) == "partial"
    assert not contributes_detected_risk("integrity", result)

    score, breakdown, maximum = calculate_risk_score({"integrity": result})

    assert score == 0
    assert breakdown["integrity"] == 0
    assert maximum == 0
    assert prioritize_findings({"integrity": result}) == []
