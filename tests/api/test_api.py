"""HTTP surface.

These are the tests `deploy.yml`'s promotion gate leans on: if a dependency bump breaks
Flask or Werkzeug, this is where it shows up before the change reaches an environment.
"""

from __future__ import annotations

from tests.conftest import SAMPLES

MANIFEST = {
    "job": {"name": "api-run"},
    "sources": [{
        "id": "image", "repo": "baobao-batch-worker", "kind": "trivy",
        "path": str(SAMPLES / "trivy-batch-worker-image.json"),
    }],
    "sink": {"endpoint": "", "batch_size": 50},
}


class TestHealth:
    def test_healthz(self, client):
        response = client.get("/healthz")
        assert response.status_code == 200

        body = response.get_json()
        assert body["status"] == "ok"
        assert body["service"] == "baobao-batch-worker"
        assert body["version"]

    def test_healthz_reports_the_deployed_image_tag(self, client):
        # deploy.yml asserts on this after a revision swap to confirm the new image is
        # actually serving, rather than trusting Azure's own status.
        assert "image_tag" in client.get("/healthz").get_json()

    def test_readyz_checks_the_database(self, client):
        response = client.get("/readyz")
        assert response.status_code == 200
        assert response.get_json()["database"] is True

    def test_unknown_route_is_json_not_html(self, client):
        response = client.get("/nope")
        assert response.status_code == 404
        assert response.get_json()["error"] == "not found"


class TestJobs:
    def test_run_with_an_inline_manifest(self, client):
        response = client.post("/api/jobs/run", json={"manifest": MANIFEST})
        assert response.status_code == 200

        body = response.get_json()
        assert body["run"]["status"] == "succeeded"
        assert body["run"]["findings_ingested"] == 9
        assert "findings" not in body  # kept out of the response; use /api/findings

    def test_run_reports_channels(self, client):
        body = client.post("/api/jobs/run", json={"manifest": MANIFEST}).get_json()
        assert body["by_channel"]["base_image_bump"] == 7

    def test_run_with_no_body_uses_the_configured_manifest(self, client):
        response = client.post("/api/jobs/run")
        assert response.status_code == 200
        assert response.get_json()["run"]["findings_ingested"] > 0

    def test_invalid_manifest_is_a_400(self, client):
        response = client.post("/api/jobs/run", json={"manifest": {"job": {}, "sources": []}})
        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid manifest"

    def test_missing_manifest_path_is_a_400(self, client):
        response = client.post("/api/jobs/run", json={"manifest": "/nonexistent.yaml"})
        assert response.status_code == 400

    def test_list_and_fetch_a_run(self, client):
        run_id = client.post("/api/jobs/run", json={"manifest": MANIFEST}).get_json()["run"]["id"]

        listed = client.get("/api/jobs").get_json()["runs"]
        assert any(r["id"] == run_id for r in listed)

        assert client.get(f"/api/jobs/{run_id}").get_json()["id"] == run_id

    def test_unknown_run_is_a_404(self, client):
        assert client.get("/api/jobs/does-not-exist").status_code == 404


class TestFindings:
    def test_empty_before_any_run(self, client):
        assert client.get("/api/findings").get_json()["count"] == 0

    def test_listed_after_a_run(self, client):
        client.post("/api/jobs/run", json={"manifest": MANIFEST})
        body = client.get("/api/findings").get_json()
        assert body["count"] == 9

    def test_worst_first(self, client):
        client.post("/api/jobs/run", json={"manifest": MANIFEST})
        findings = client.get("/api/findings").get_json()["findings"]
        assert findings[0]["severity"] == "CRITICAL"

    def test_filter_by_severity(self, client):
        client.post("/api/jobs/run", json={"manifest": MANIFEST})
        body = client.get("/api/findings?severity=critical").get_json()
        assert body["count"] == 2
        assert all(f["severity"] == "CRITICAL" for f in body["findings"])

    def test_filter_by_channel(self, client):
        client.post("/api/jobs/run", json={"manifest": MANIFEST})
        body = client.get("/api/findings?channel=base_image_bump").get_json()
        assert body["count"] == 7

    def test_filter_by_repo(self, client):
        client.post("/api/jobs/run", json={"manifest": MANIFEST})
        assert client.get("/api/findings?repo=baobao-payments-api").get_json()["count"] == 0

    def test_limit_is_clamped(self, client):
        client.post("/api/jobs/run", json={"manifest": MANIFEST})
        assert client.get("/api/findings?limit=3").get_json()["count"] == 3
        assert client.get("/api/findings?limit=banana").get_json()["count"] == 9


class TestMetrics:
    def test_aggregates(self, client):
        client.post("/api/jobs/run", json={"manifest": MANIFEST})
        body = client.get("/metrics").get_json()

        assert body["by_severity"]["CRITICAL"] == 2
        assert body["by_channel"]["base_image_bump"] == 7
        assert body["by_repo"]["baobao-batch-worker"] == 9
        assert body["by_scanner"]["trivy"] == 9
