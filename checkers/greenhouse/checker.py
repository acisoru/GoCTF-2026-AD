#!/usr/bin/env python3
"""Skipper/Forcad checker for the three Greenhouse flag places."""
import hashlib
import json
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request

OK, CORRUPT, MUMBLE, DOWN, FAILED = 101, 102, 103, 104, 110


def finish(status, public, private=""):
    print(public)
    print(private or public, file=sys.stderr)
    raise SystemExit(status)


def api(host, method, path, payload=None, key=""):
    request = urllib.request.Request(
        f"http://{host}:8080{path}", method=method,
        data=json.dumps(payload).encode() if payload is not None else None,
        headers={"Content-Type": "application/json", "X-Greenhouse-Key": key})
    with urllib.request.urlopen(request, timeout=4) as response:
        return json.load(response)


class Console:
    def __init__(self, host):
        self.host = host
        self.session = api(host, "POST", "/api/console/open", {})["session"]

    def command(self, line):
        return api(self.host, "POST", "/api/console/command",
                   {"session": self.session, "command": line})["reply"]

    def close(self):
        try:
            api(self.host, "POST", "/api/console/close", {"session": self.session})
        except (OSError, urllib.error.URLError):
            pass


def cap(flag):
    return hashlib.sha256(flag.encode()).hexdigest()[:32]


def run(args):
    if args == ["info"]:
        finish(OK, json.dumps({"vulns": 3, "timeout": 10, "attack_data": True, "puts": 1, "gets": 1}))
    if len(args) == 2 and args[0] == "check":
        host = args[1]
        status = api(host, "GET", "/api/status")
        plots = api(host, "GET", "/api/plots")
        if status.get("module") != "ОРАНЖЕРЕЯ" or not plots.get("plots"):
            finish(MUMBLE, "Bad greenhouse telemetry")
        console = Console(host)
        result = console.command("HELP")
        console.close()
        if "OBSERVE" not in result:
            finish(MUMBLE, "Native console malformed")
        finish(OK, "OK")
    if len(args) != 5 or args[0] not in {"put", "get"}:
        finish(FAILED, "Checker arguments invalid")
    action, host, flag_id, flag, vuln_text = args
    vuln = int(vuln_text)
    if vuln not in {1, 2, 3}:
        finish(FAILED, "Invalid vuln")
    key = cap(flag)
    if action == "put":
        if vuln == 1:
            console = Console(host)
            result = console.command(f"SOW {flag} {key}")
            console.close()
            if not result.startswith("SOWN "):
                finish(MUMBLE, "Could not sow specimen", result)
            finish(OK, result.split()[1])
        payload = {"name": f"Биокупол {flag_id[:12]}", "cultivar": "Quantum fern",
                   "note": flag if vuln == 2 else "Штатная биометрия",
                   "archive": flag if vuln == 3 else "Штатная архивная запись", "key": key}
        result = api(host, "POST", "/api/plots", payload)
        if not result.get("id"):
            finish(MUMBLE, "Could not create plot")
        finish(OK, result["id"])
    if vuln == 1:
        console = Console(host)
        result = console.command(f"READ {flag_id} {key}")
        console.close()
        if result != f"SPECIMEN {flag}":
            finish(CORRUPT, "Specimen lost", result)
        finish(OK, "OK")
    quoted = urllib.parse.quote(flag_id, safe="")
    if vuln == 2:
        result = api(host, "GET", f"/api/plots/{quoted}", key=key)
        recovered = result.get("note")
    else:
        result = api(host, "GET", f"/api/archive?plot={quoted}", key=key)
        recovered = result.get("archive")
    if recovered != flag:
        finish(CORRUPT, "Flag record corrupted")
    finish(OK, "OK")


if __name__ == "__main__":
    try:
        run(sys.argv[1:])
    except urllib.error.HTTPError as exc:
        action = sys.argv[1] if len(sys.argv) > 1 else ""
        finish(DOWN if exc.code >= 500 else CORRUPT if action == "get" else MUMBLE,
               "Flag record unavailable" if action == "get" else "Greenhouse request failed",
               f"HTTP {exc.code}: {exc.reason}")
    except (socket.timeout, ConnectionError, urllib.error.URLError, OSError) as exc:
        finish(DOWN, "Greenhouse unavailable", str(exc))
    except (ValueError, KeyError, json.JSONDecodeError) as exc:
        finish(MUMBLE, "Greenhouse response malformed", str(exc))
