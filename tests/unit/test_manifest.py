from __future__ import annotations

import pytest

from app.manifest import ManifestError, load_manifest, parse_manifest
from tests.conftest import SAMPLES

VALID = {
    "job": {"name": "nightly"},
    "sources": [{"id": "s1", "repo": "r1", "kind": "trivy", "path": "x.json"}],
    "sink": {"endpoint": "https://baobao.example/api/ingest/scanner", "batch_size": 10},
}


class TestParse:
    def test_happy_path(self):
        manifest = parse_manifest(VALID)
        assert manifest.name == "nightly"
        assert manifest.source_count == 1
        assert manifest.batch_size == 10

    def test_committed_manifest_loads(self):
        manifest = load_manifest(SAMPLES / "job-manifest.yaml")
        assert manifest.source_count == 3
        assert {s.repo for s in manifest.sources} == {
            "baobao-batch-worker", "baobao-payments-api",
        }

    def test_committed_manifest_sources_all_exist(self):
        # Guards the "clone and run" promise: a renamed sample would otherwise only
        # surface as a runtime source error.
        manifest = load_manifest(SAMPLES / "job-manifest.yaml")
        for source in manifest.sources:
            assert (SAMPLES.parent / source.path).is_file(), source.path


class TestValidation:
    def test_rejects_a_non_mapping_root(self):
        with pytest.raises(ManifestError):
            parse_manifest(["not", "a", "mapping"])

    def test_rejects_an_empty_source_list(self):
        with pytest.raises(ManifestError, match="at least one source"):
            parse_manifest({"job": {"name": "n"}, "sources": []})

    def test_rejects_an_unknown_scanner(self):
        bad = {**VALID, "sources": [{"id": "s", "repo": "r", "kind": "nessus", "path": "x"}]}
        with pytest.raises(ManifestError, match="unsupported kind"):
            parse_manifest(bad)

    def test_rejects_a_source_with_no_location(self):
        bad = {**VALID, "sources": [{"id": "s", "repo": "r", "kind": "trivy"}]}
        with pytest.raises(ManifestError, match="path, url or archive"):
            parse_manifest(bad)

    def test_rejects_a_source_with_no_repo(self):
        bad = {**VALID, "sources": [{"id": "s", "kind": "trivy", "path": "x"}]}
        with pytest.raises(ManifestError, match="`repo` is required"):
            parse_manifest(bad)

    def test_rejects_duplicate_source_ids(self):
        # Duplicate ids would make a source error unattributable in the run summary.
        bad = {**VALID, "sources": [
            {"id": "s", "repo": "r", "kind": "trivy", "path": "a.json"},
            {"id": "s", "repo": "r", "kind": "trivy", "path": "b.json"},
        ]}
        with pytest.raises(ManifestError, match="duplicate source id"):
            parse_manifest(bad)

    def test_rejects_a_non_integer_batch_size(self):
        with pytest.raises(ManifestError, match="batch_size"):
            parse_manifest({**VALID, "sink": {"batch_size": "lots"}})

    def test_missing_file(self, tmp_path):
        with pytest.raises(ManifestError, match="not found"):
            load_manifest(tmp_path / "nope.yaml")

    def test_invalid_yaml(self, tmp_path):
        path = tmp_path / "bad.yaml"
        path.write_text("job: [unclosed", encoding="utf-8")
        with pytest.raises(ManifestError, match="invalid YAML"):
            load_manifest(path)

    def test_yaml_object_tags_are_not_constructed(self, tmp_path):
        # safe_load, not load. If this ever regresses to yaml.load the repo would have
        # a second, unintended deserialisation vulnerability — and an unintended one is
        # the kind that ruins a demo.
        path = tmp_path / "evil.yaml"
        path.write_text("job: !!python/object/apply:os.system ['echo pwned']\n", encoding="utf-8")
        with pytest.raises(ManifestError):
            load_manifest(path)
