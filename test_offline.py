import app, socket, json

original = socket.create_connection
calls = []


def local_only(address, *args, **kwargs):
    host = address[0]
    if host not in ["127.0.0.1", "localhost", "::1"]:
        raise RuntimeError(
            "External networking forbidden during runtime check: " + host
        )
    calls.append(host)
    return original(address, *args, **kwargs)


socket.create_connection = local_only
result = app.infer(
    "offline-loopback-check",
    "benign",
    {
        "logs": [
            {
                "line": 1,
                "event": {
                    "client_ip": "192.0.2.42",
                    "method": "GET",
                    "path": "/",
                    "status": 200,
                },
            }
        ],
        "prior_facts": [],
    },
    {1},
)
assert not result, result
summary = {
    "pass": True,
    "result": result,
    "external_connections_allowed": False,
    "loopback_connections": len(calls),
    "limitation": "Python-side runtime smoke test with external connections rejected; host network adapters were not disabled.",
}
open("OFFLINE_RESULTS.json", "w").write(json.dumps(summary, indent=2))
print(summary)
