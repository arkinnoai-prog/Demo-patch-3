"""Archive handling — the *non*-security half.

The traversal guard `_is_within` is tested here and is correct; what is missing in the
seeded state is that `extract_bundle` never calls it.  That gap is proven by
`tests/security/test_archive_traversal.py`, which is excluded from the default run.

Keeping the guard tested but unused is deliberate: it makes the AI patch a three-line
call-site change with the whole suite already green behind it, which is what earns a
high deterministic confidence score (POC-PLAN.md §7).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.jobs.archive import ArchiveError, _is_within, extract_bundle, read_member


class TestIsWithin:
    def test_direct_child(self, tmp_path: Path):
        assert _is_within(tmp_path, tmp_path / "a.json") is True

    def test_nested_child(self, tmp_path: Path):
        assert _is_within(tmp_path, tmp_path / "a" / "b" / "c.json") is True

    def test_the_root_itself(self, tmp_path: Path):
        assert _is_within(tmp_path, tmp_path) is True

    def test_parent_traversal(self, tmp_path: Path):
        assert _is_within(tmp_path, tmp_path / ".." / "escaped.txt") is False

    def test_deep_traversal(self, tmp_path: Path):
        assert _is_within(tmp_path, tmp_path / "a" / ".." / ".." / "escaped.txt") is False

    def test_absolute_path_outside(self, tmp_path: Path):
        assert _is_within(tmp_path, Path(tmp_path.anchor) / "etc" / "passwd") is False

    def test_sibling_with_a_shared_prefix(self, tmp_path: Path):
        # `/tmp/root-evil` must not count as inside `/tmp/root` — a string-prefix
        # implementation of this guard passes every other test here and fails this one.
        root = tmp_path / "root"
        root.mkdir()
        assert _is_within(root, tmp_path / "root-evil" / "x.txt") is False


class TestExtractBundle:
    def test_extracts_a_well_formed_bundle(self, tmp_path: Path, make_tar):
        bundle = make_tar("ok.tar.gz", [("report.json", '{"a": 1}'), ("meta.txt", "hello")])
        written = extract_bundle(bundle, tmp_path / "out")

        assert (tmp_path / "out" / "report.json").read_text() == '{"a": 1}'
        assert len(written) == 2

    def test_creates_the_destination(self, tmp_path: Path, make_tar):
        bundle = make_tar("ok.tar.gz", [("report.json", "{}")])
        extract_bundle(bundle, tmp_path / "deep" / "nested" / "out")
        assert (tmp_path / "deep" / "nested" / "out" / "report.json").is_file()

    def test_missing_bundle(self, tmp_path: Path):
        with pytest.raises(ArchiveError, match="not found"):
            extract_bundle(tmp_path / "nope.tar.gz", tmp_path / "out")

    def test_not_a_tar(self, tmp_path: Path):
        bogus = tmp_path / "bogus.tar.gz"
        bogus.write_bytes(b"this is not a tarball")
        with pytest.raises(ArchiveError, match="could not read"):
            extract_bundle(bogus, tmp_path / "out")

    def test_rejects_too_many_members(self, tmp_path: Path, make_tar, monkeypatch):
        import app.jobs.archive as archive_module

        monkeypatch.setattr(archive_module, "MAX_MEMBERS", 2)
        bundle = make_tar("many.tar.gz", [(f"f{i}.txt", "x") for i in range(5)])
        with pytest.raises(ArchiveError, match="limit is 2"):
            extract_bundle(bundle, tmp_path / "out")

    def test_rejects_an_oversized_expansion(self, tmp_path: Path, make_tar, monkeypatch):
        import app.jobs.archive as archive_module

        monkeypatch.setattr(archive_module, "MAX_UNCOMPRESSED_BYTES", 10)
        bundle = make_tar("big.tar.gz", [("f.txt", "x" * 100)])
        with pytest.raises(ArchiveError, match="expands to"):
            extract_bundle(bundle, tmp_path / "out")


class TestReadMember:
    def test_exact_path(self, tmp_path: Path, make_tar):
        bundle = make_tar("b.tar.gz", [("report.json", "{}"), ("other.json", "[]")])
        assert read_member(bundle, "report.json", tmp_path / "w").read_text() == "{}"

    def test_falls_back_to_a_basename_match(self, tmp_path: Path, make_tar):
        # CI bundles are usually nested under a run directory.
        bundle = make_tar("b.tar.gz", [("run-128/trivy/report.json", '{"n": 1}')])
        assert read_member(bundle, "report.json", tmp_path / "w").read_text() == '{"n": 1}'

    def test_absent_member(self, tmp_path: Path, make_tar):
        bundle = make_tar("b.tar.gz", [("report.json", "{}")])
        with pytest.raises(ArchiveError, match="not found in"):
            read_member(bundle, "missing.json", tmp_path / "w")
