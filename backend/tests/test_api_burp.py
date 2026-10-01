import base64


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


RESPONSE_WITH_HSTS = (
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html\r\n"
    "Strict-Transport-Security: max-age=31536000\r\n"
    "\r\n"
    "<html/>"
)
RESPONSE_WITHOUT_HSTS = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html/>"


def _burp_xml() -> bytes:
    return f"""<?xml version="1.0"?>
<items>
<item>
<url><![CDATA[https://a.example.com/page]]></url>
<host ip="1.1.1.1">a.example.com</host>
<port>443</port>
<method>GET</method>
<path><![CDATA[/page]]></path>
<status>200</status>
<mimetype>HTML</mimetype>
<response base64="true">{_b64(RESPONSE_WITH_HSTS)}</response>
</item>
<item>
<url><![CDATA[https://b.example.com/other]]></url>
<host ip="2.2.2.2">b.example.com</host>
<port>443</port>
<method>GET</method>
<path><![CDATA[/other]]></path>
<status>200</status>
<mimetype>HTML</mimetype>
<response base64="true">{_b64(RESPONSE_WITHOUT_HSTS)}</response>
</item>
</items>""".encode()


def _upload(client) -> dict:
    resp = client.post(
        "/api/burp/import",
        files={"file": ("history.xml", _burp_xml(), "text/xml")},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def _baseline_policy_id(client) -> str:
    baselines = client.get("/api/policies/baselines").json()
    return baselines[0]["id"]


class TestImport:
    def test_requires_auth(self, client):
        resp = client.post("/api/burp/import", files={"file": ("h.xml", b"<items></items>", "text/xml")})
        assert resp.status_code == 401

    def test_uploads_and_parses(self, auth_client):
        client, _ = auth_client
        body = _upload(client)
        assert body["entries_found"] == 2
        assert body["parsed_count"] == 2
        assert body["failed_count"] == 0
        assert set(body["facets"]["hosts"]) == {"a.example.com", "b.example.com"}
        assert body["name"] == "Burp History - history"

    def test_invalid_file_is_422(self, auth_client):
        client, _ = auth_client
        resp = client.post("/api/burp/import", files={"file": ("h.xml", b"not xml", "text/xml")})
        assert resp.status_code == 422

    def test_no_entries_is_422(self, auth_client):
        client, _ = auth_client
        resp = client.post(
            "/api/burp/import", files={"file": ("h.xml", b"<?xml version=\"1.0\"?><items></items>", "text/xml")}
        )
        assert resp.status_code == 422


class TestAnalyze:
    def test_requires_auth(self, client):
        resp = client.post("/api/burp/nope/analyze", json={"policy_id": "x"})
        assert resp.status_code == 401

    def test_import_not_found_404(self, auth_client):
        client, _ = auth_client
        resp = client.post("/api/burp/does-not-exist/analyze", json={"policy_id": _baseline_policy_id(client)})
        assert resp.status_code == 404

    def test_policy_not_found_404(self, auth_client):
        client, _ = auth_client
        summary = _upload(client)
        resp = client.post(f"/api/burp/{summary['id']}/analyze", json={"policy_id": "does-not-exist"})
        assert resp.status_code == 404

    def test_analyzes_and_aggregates(self, auth_client):
        client, _ = auth_client
        summary = _upload(client)
        policy_id = _baseline_policy_id(client)

        resp = client.post(f"/api/burp/{summary['id']}/analyze", json={"policy_id": policy_id})
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["status"] == "analyzed"
        assert body["policy_id"] == policy_id
        analysis = body["analysis"]
        assert analysis["summary"]["responses_analyzed"] == 2
        assert analysis["summary"]["unique_hosts"] == 2
        assert {row["host"] for row in analysis["host_summary"]} == {"a.example.com", "b.example.com"}
        # Exactly one host is missing HSTS - that's a real finding.
        hsts_findings = [f for f in analysis["findings"] if "Strict-Transport-Security" in f["header"]]
        assert len(hsts_findings) == 1
        assert hsts_findings[0]["affected_count"] == 1

    def test_target_type_is_stored_and_defaults_to_web_application(self, auth_client):
        client, _ = auth_client
        policy_id = _baseline_policy_id(client)
        summary = _upload(client)
        resp = client.post(
            f"/api/burp/{summary['id']}/analyze", json={"policy_id": policy_id, "target_type": "rest_api"}
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["target_type"] == "rest_api"
        assert body["analysis"]["target_type"] == "rest_api"
        assert body["analysis"]["summary"]["checks"] is not None

        other = _upload(client)
        default = client.post(f"/api/burp/{other['id']}/analyze", json={"policy_id": policy_id}).json()
        assert default["target_type"] == "web_application"

    def test_invalid_target_type_is_422(self, auth_client):
        client, _ = auth_client
        summary = _upload(client)
        resp = client.post(
            f"/api/burp/{summary['id']}/analyze",
            json={"policy_id": _baseline_policy_id(client), "target_type": "Web Application"},
        )
        assert resp.status_code == 422

    def test_host_filter_narrows_analysis(self, auth_client):
        client, _ = auth_client
        summary = _upload(client)
        policy_id = _baseline_policy_id(client)

        resp = client.post(
            f"/api/burp/{summary['id']}/analyze",
            json={"policy_id": policy_id, "filters": {"hosts": ["a.example.com"], "deduplicate": False}},
        )
        assert resp.status_code == 200
        analysis = resp.json()["analysis"]
        assert analysis["summary"]["responses_analyzed"] == 1
        assert analysis["summary"]["unique_hosts"] == 1
        assert len(analysis["import_issues"]) == 1
        assert analysis["import_issues"][0]["reason"] == "Excluded by host filter."

    def test_custom_report_name_is_used(self, auth_client):
        client, _ = auth_client
        summary = _upload(client)
        policy_id = _baseline_policy_id(client)
        resp = client.post(
            f"/api/burp/{summary['id']}/analyze",
            json={"policy_id": policy_id, "name": "My Burp Assessment"},
        )
        assert resp.json()["name"] == "My Burp Assessment"


class TestListGetDelete:
    def test_list_requires_auth(self, client):
        assert client.get("/api/burp").status_code == 401

    def test_list_and_get(self, auth_client):
        client, _ = auth_client
        summary = _upload(client)

        listed = client.get("/api/burp").json()
        assert any(item["id"] == summary["id"] for item in listed)

        got = client.get(f"/api/burp/{summary['id']}").json()
        assert got["id"] == summary["id"]
        assert got["status"] == "parsed"
        assert got["analysis"] is None

    def test_other_users_import_is_404(self, auth_client, make_user, client):
        summary = _upload(client)
        make_user()  # logs the new user in on the shared client/cookie jar
        resp = client.get(f"/api/burp/{summary['id']}")
        assert resp.status_code == 404

    def test_delete(self, auth_client):
        client, _ = auth_client
        summary = _upload(client)
        assert client.delete(f"/api/burp/{summary['id']}").status_code == 204
        assert client.get(f"/api/burp/{summary['id']}").status_code == 404

    def test_delete_requires_auth(self, client):
        assert client.delete("/api/burp/whatever").status_code == 401


class TestExport:
    def test_requires_auth(self, client):
        assert client.get("/api/burp/whatever/export").status_code == 401

    def test_not_found_404(self, auth_client):
        client, _ = auth_client
        assert client.get("/api/burp/does-not-exist/export").status_code == 404

    def test_not_yet_analyzed_is_409(self, auth_client):
        client, _ = auth_client
        summary = _upload(client)
        resp = client.get(f"/api/burp/{summary['id']}/export")
        assert resp.status_code == 409

    def test_other_users_import_is_404(self, auth_client, make_user, client):
        summary = _upload(client)
        make_user()
        resp = client.get(f"/api/burp/{summary['id']}/export")
        assert resp.status_code == 404

    def test_downloads_workbook_after_analysis(self, auth_client):
        client, _ = auth_client
        summary = _upload(client)
        policy_id = _baseline_policy_id(client)
        client.post(f"/api/burp/{summary['id']}/analyze", json={"policy_id": policy_id})

        resp = client.get(f"/api/burp/{summary['id']}/export")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        assert "attachment" in resp.headers["content-disposition"]
        assert "Security Header Analysis.xlsx" in resp.headers["content-disposition"]
        # A real workbook, not just bytes with the right content-type.
        import io

        import openpyxl

        wb = openpyxl.load_workbook(io.BytesIO(resp.content))
        assert "Endpoint Analysis" in wb.sheetnames
