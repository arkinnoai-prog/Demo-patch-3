"""The remediation router and normalisation rules.

This is the regression suite that a bad patch trips (CVE scenario 8).  It is
deliberately the most thoroughly tested module in the repo: the router is what decides
whether a finding reaches an LLM at all, so a silent regression here would be both
expensive and invisible.
"""

from __future__ import annotations

import pytest

from app.normalise import (
    dedupe,
    enrich,
    fingerprint,
    is_major_bump,
    normalise_severity,
    route_remediation,
    severity_from_cvss,
    summarise,
)


class TestSeverity:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("CRITICAL", "CRITICAL"),
            ("critical", "CRITICAL"),
            ("  High  ", "HIGH"),
            ("Important", "HIGH"),  # Red Hat's vocabulary
            ("Moderate", "MEDIUM"),  # GitHub's vocabulary
            ("Negligible", "LOW"),  # Grype's vocabulary
            ("", "UNKNOWN"),
            ("nonsense", "UNKNOWN"),
        ],
    )
    def test_aliases(self, raw, expected):
        assert normalise_severity(raw) == expected

    @pytest.mark.parametrize(
        "score,expected",
        [(9.8, "CRITICAL"), (9.0, "CRITICAL"), (8.9, "HIGH"), (7.0, "HIGH"),
         (6.9, "MEDIUM"), (4.0, "MEDIUM"), (3.9, "LOW"), (0.1, "LOW"), (0.0, "UNKNOWN")],
    )
    def test_severity_from_cvss(self, score, expected):
        assert severity_from_cvss(score) == expected

    def test_cvss_fills_in_missing_severity(self, make_finding):
        finding = make_finding(severity="", cvss=9.4)
        assert enrich([finding])[0].severity == "CRITICAL"

    def test_explicit_severity_wins_over_cvss(self, make_finding):
        finding = make_finding(severity="LOW", cvss=9.8)
        assert enrich([finding])[0].severity == "LOW"


class TestMajorBump:
    @pytest.mark.parametrize(
        "installed,fixed,expected",
        [
            ("1.26.4", "1.26.18", False),
            ("2.25.1", "2.31.0", False),
            ("2.0.3", "3.0.3", True),
            ("2.10", "3.7", True),
            ("20.1.0", "22.0.0", True),
            ("", "1.2.3", True),  # unknown → a human looks at it
            ("1.2.3", "", True),
        ],
    )
    def test_semver(self, installed, fixed, expected):
        assert is_major_bump(installed, fixed) is expected

    def test_calver_is_not_a_major_bump(self):
        # certifi. A year-shaped major on both sides means CalVer, and CalVer packages
        # carry no API to break. Getting this wrong sends a cert bundle to the LLM.
        assert is_major_bump("2021.5.30", "2024.7.4") is False
        assert is_major_bump("2021.5.30", "2022.12.7") is False


class TestRouter:
    def test_os_package_on_an_image_is_a_base_image_bump(self, make_finding):
        finding = make_finding(target_class="os-pkgs", artifact_type="container_image")
        assert route_remediation(finding) == "base_image_bump"

    def test_os_package_on_a_vm_is_an_os_package_bump(self, make_finding):
        # Same finding class, different remediation channel — this one distinction is
        # what separates baobao-batch-worker's scenario from baobao-legacy-vm's.
        finding = make_finding(target_class="os-pkgs", artifact_type="vm")
        assert route_remediation(finding) == "os_package"

    def test_clean_semver_fix_is_mechanical(self, make_finding):
        finding = make_finding(installed_version="1.26.4", fixed_version="1.26.18")
        assert route_remediation(finding) == "dependency_bump"

    def test_major_bump_escalates_to_the_llm(self, make_finding):
        finding = make_finding(installed_version="2.0.3", fixed_version="3.0.3")
        assert route_remediation(finding) == "ai_code_fix"

    def test_sast_finding_always_escalates(self, make_finding):
        # POC-PLAN.md §7 guardrail: a logic change never goes through mechanically,
        # even when a fixed version happens to be present.
        finding = make_finding(source_scanner="bandit", target_class="", fixed_version="1.0.1")
        assert route_remediation(finding) == "ai_code_fix"

    def test_iac_finding_routes_to_terraform(self, make_finding):
        finding = make_finding(source_scanner="checkov", target_class="config")
        assert route_remediation(finding) == "iac_fix"

    def test_no_fix_available_becomes_a_work_item(self, make_finding):
        # Scenario 7's shape: nothing to bump to, so it is a human decision.
        finding = make_finding(fixed_version="")
        assert route_remediation(finding) == "none"

    def test_no_fix_available_never_reaches_the_llm(self, make_finding):
        finding = make_finding(fixed_version="", severity="CRITICAL")
        assert route_remediation(finding) != "ai_code_fix"


class TestFingerprintAndDedupe:
    def test_fingerprint_is_stable_across_versions(self, make_finding):
        a = make_finding(installed_version="1.0.0")
        b = make_finding(installed_version="1.0.5")
        assert fingerprint(a) == fingerprint(b)

    def test_fingerprint_ignores_the_scanner(self, make_finding):
        trivy = make_finding(source_scanner="trivy", target="app/requirements.txt")
        pip = make_finding(source_scanner="pip-audit", target="requirements.txt")
        assert fingerprint(trivy) == fingerprint(pip)

    def test_fingerprint_separates_repos(self, make_finding):
        a = make_finding(repo="baobao-batch-worker")
        b = make_finding(repo="baobao-payments-api")
        assert fingerprint(a) != fingerprint(b)

    def test_dedupe_collapses_cross_scanner_duplicates(self, make_finding):
        findings = enrich([
            make_finding(source_scanner="trivy", severity="HIGH"),
            make_finding(source_scanner="pip-audit", severity=""),
        ])
        result = dedupe(findings)
        assert len(result) == 1

    def test_dedupe_keeps_the_highest_severity(self, make_finding):
        findings = enrich([
            make_finding(source_scanner="pip-audit", severity=""),
            make_finding(source_scanner="trivy", severity="CRITICAL"),
        ])
        assert dedupe(findings)[0].severity == "CRITICAL"

    def test_dedupe_sorts_worst_first(self, make_finding):
        findings = enrich([
            make_finding(vuln_id="CVE-1", package_name="a", severity="LOW"),
            make_finding(vuln_id="CVE-2", package_name="b", severity="CRITICAL"),
            make_finding(vuln_id="CVE-3", package_name="c", severity="MEDIUM"),
        ])
        assert [f.severity for f in dedupe(findings)] == ["CRITICAL", "MEDIUM", "LOW"]


class TestSummarise:
    def test_mechanical_ratio(self, make_finding):
        findings = enrich([
            make_finding(vuln_id="CVE-1", package_name="a",
                         installed_version="1.0.0", fixed_version="1.0.1"),
            make_finding(vuln_id="CVE-2", package_name="b",
                         target_class="os-pkgs", artifact_type="container_image"),
            make_finding(vuln_id="CVE-3", package_name="c",
                         installed_version="1.0.0", fixed_version="9.0.0"),
            make_finding(vuln_id="CVE-4", package_name="d", source_scanner="codeql"),
        ])
        _, by_channel, ratio = summarise(findings)
        assert ratio == 0.5
        assert by_channel["ai_code_fix"] == 2

    def test_empty_input(self):
        by_severity, by_channel, ratio = summarise([])
        assert ratio == 0.0
        assert by_channel == {}
        assert by_severity["CRITICAL"] == 0
