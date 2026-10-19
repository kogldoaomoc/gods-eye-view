import json
import threading
import urllib.request

from casefile.server import make_server


def _request(base, method, path, body=None, token=None):
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(base + path, data=data, method=method)
    request.add_header("Content-Type", "application/json")
    if token:
        request.add_header("X-Casefile-Token", token)
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read().decode())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read().decode())


def _serve(tmp_path, token=None):
    httpd = make_server(str(tmp_path), port=0, token=token, workers=1)
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, base


def test_health_is_unauthenticated(tmp_path):
    httpd, base = _serve(tmp_path, token="secret")
    try:
        status, payload = _request(base, "GET", "/api/health")
        assert status == 200 and payload["ok"] is True
        status, _ = _request(base, "GET", "/api/cases")
        assert status == 401
    finally:
        httpd.shutdown()
        httpd.bridge.close()


def test_case_lifecycle_and_tools(tmp_path):
    httpd, base = _serve(tmp_path)
    try:
        status, tools = _request(base, "GET", "/api/tools")
        assert status == 200
        assert any(t["name"] == "spiderfoot" for t in tools["tools"])
        status, case = _request(base, "POST", "/api/cases", {"name": "Op Test"})
        assert status == 201
        case_id = case["id"]
        status, listing = _request(base, "GET", "/api/cases")
        assert any(c["id"] == case_id for c in listing["cases"])
        status, entities = _request(base, "GET", f"/api/cases/{case_id}/entities")
        assert status == 200 and entities["entities"] == []
        status, out = _request(base, "DELETE", f"/api/cases/{case_id}")
        assert status == 200 and out["deleted"] is True
    finally:
        httpd.shutdown()
        httpd.bridge.close()


def test_unknown_case_is_404(tmp_path):
    httpd, base = _serve(tmp_path)
    try:
        status, _ = _request(base, "GET", "/api/cases/case_000000000000/entities")
        assert status == 404
    finally:
        httpd.shutdown()
        httpd.bridge.close()
