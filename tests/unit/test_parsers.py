from __future__ import annotations

import pytest

from app import parsers
from app.parsers import pip_audit, trivy


class TestTrivy:
    def test_parses_the_committed_image_report(self, sample):
        findings = trivy.parse(sample("trivy-batch-worker-image.json"), "baobao-batch-worker")
        assert len(findings) == 9

        ids = {f.vuln_id for f in findings}
        assert "CVE-2023-45853" in ids  # the zlib critical — scenario 3's headline
        assert "CVE-2024-1135" in ids  # gunicorn, from the lang-pkgs result

    def test_marks_the_artifact_type(self, sample):
        findings = trivy.parse(sample("trivy-batch-worker-image.json"), "baobao-batch-worker")
        os_pkgs = [f for f in findings if f.target_class == "os-pkgs"]
        assert os_pkgs and all(f.artifact_type == "container_image" for f in os_pkgs)

    def test_takes_the_highest_cvss_across_scoring_sources(self, sample):
        findings = trivy.parse(sample("trivy-batch-worker-image.json"), "baobao-batch-worker")
        zlib = next(f for f in findings if f.vuln_id == "CVE-2023-45853")
        # nvd says 9.8, redhat says 7.5 — the conservative read is the higher one.
        assert zlib.cvss == 9.8

    def test_missing_fixed_version_is_empty_not_none(self, sample):
        findings = trivy.parse(sample("trivy-batch-worker-image.json"), "baobao-batch-worker")
        gpgv = next(f for f in findings if f.package_name == "gpgv")
        assert gpgv.fixed_version == ""

    def test_repository_scan_artifact_type(self, sample):
        findings = trivy.parse(sample("trivy-payments-api-fs.json"), "baobao-payments-api")
        assert len(findings) == 4
        assert all(f.artifact_type == "repository" for f in findings)

    def test_takes_the_first_of_several_fix_candidates(self):
        document = {
            "ArtifactType": "container_image",
            "Results": [{
                "Target": "img", "Class": "os-pkgs",
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-X", "PkgName": "p",
                    "InstalledVersion": "1.0", "FixedVersion": "1.1, 2.0", "Severity": "HIGH",
                }],
            }],
        }
        assert trivy.parse(document, "r")[0].fixed_version == "1.1"

    @pytest.mark.parametrize("document", [{}, {"Results": None}, {"Results": []}, [], "nope"])
    def test_tolerates_malformed_documents(self, document):
        assert trivy.parse(document, "r") == []

    def test_skips_entries_without_an_id(self):
        document = {"Results": [{"Target": "t", "Vulnerabilities": [{"PkgName": "p"}]}]}
        assert trivy.parse(document, "r") == []


class TestPipAudit:
    def test_parses_the_committed_report(self, sample):
        findings = pip_audit.parse(sample("pip-audit-batch-worker.json"), "baobao-batch-worker")
        # 12 vulns across the declared dependencies; sqlalchemy and pyyaml are clean.
        assert len(findings) == 12
        assert {f.package_name for f in findings} == {
            "flask", "werkzeug", "jinja2", "urllib3", "idna",
            "certifi", "pygments", "requests", "gunicorn",
        }

    def test_prefers_the_cve_alias_over_the_ghsa_id(self, sample):
        findings = pip_audit.parse(sample("pip-audit-batch-worker.json"), "baobao-batch-worker")
        flask = next(f for f in findings if f.package_name == "flask")
        assert flask.vuln_id == "CVE-2023-30861"

    def test_severity_is_left_unknown_rather_than_invented(self, sample):
        findings = pip_audit.parse(sample("pip-audit-batch-worker.json"), "baobao-batch-worker")
        assert all(f.severity == "" for f in findings)

    def test_takes_the_lowest_fix_version(self, sample):
        findings = pip_audit.parse(sample("pip-audit-batch-worker.json"), "baobao-batch-worker")
        flask = next(f for f in findings if f.package_name == "flask")
        assert flask.fixed_version == "2.2.5"  # not 2.3.2

    def test_accepts_the_bare_list_shape(self):
        document = [{"name": "flask", "version": "2.0.1",
                     "vulns": [{"id": "CVE-1", "fix_versions": ["2.2.5"]}]}]
        assert len(pip_audit.parse(document, "r")) == 1

    @pytest.mark.parametrize("document", [{}, [], None, "nope", {"dependencies": None}])
    def test_tolerates_malformed_documents(self, document):
        assert pip_audit.parse(document, "r") == []

    def test_clean_dependency_yields_nothing(self):
        document = {"dependencies": [{"name": "x", "version": "1", "vulns": []}]}
        assert pip_audit.parse(document, "r") == []


class TestRegistry:
    def test_dispatches_by_kind(self, sample):
        assert parsers.parse("trivy", sample("trivy-payments-api-fs.json"), "r")

    def test_unknown_scanner_raises(self):
        with pytest.raises(parsers.UnknownScannerError):
            parsers.parse("nessus", {}, "r")
