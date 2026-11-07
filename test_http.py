import urllib.request, urllib.error, json

base = "http://127.0.0.1:8000"
checks = []
for name, body, headers, expected in [
    ("empty", b"", {"X-Filename": "x.log"}, 400),
    ("wrong extension", b"hello", {"X-Filename": "x.exe"}, 400),
    ("binary", b"a\x00b", {"X-Filename": "x.log"}, 400),
    (
        "foreign origin",
        b"hello",
        {"X-Filename": "x.log", "Origin": "https://example.com"},
        403,
    ),
]:
    try:
        r = urllib.request.urlopen(
            urllib.request.Request(base + "/api/upload", data=body, headers=headers)
        )
        status = r.status
    except urllib.error.HTTPError as e:
        status = e.code
    assert status == expected, (name, status)
    checks.append({"test": name, "status": status, "pass": True})
with urllib.request.urlopen(base + "/") as r:
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    checks.append({"test": "dashboard and response headers", "pass": True})
print(json.dumps(checks, indent=2))
open("HTTP_RESULTS.json", "w").write(json.dumps(checks, indent=2))
