#!/usr/bin/env python3
import json
import sys
import traceback

import requests
from checklib import BaseChecker, Status, cquit

from scenarios import cargo, contract, health, review


SCENARIOS = {"1": cargo, "2": review, "3": contract}


class Checker(BaseChecker):
    vulns = len(SCENARIOS)
    timeout = 10
    uses_attack_data = True

    def action(self, action, *args, **kwargs):
        try:
            super().action(action, *args, **kwargs)
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as exc:
            try:
                response = requests.get(f"http://{self.host}:8090/health", timeout=2)
                if response.status_code == 200:
                    self.cquit(Status.MUMBLE, "Service error", f"Starpost is up, but an operation failed: {type(exc).__name__}")
            except requests.exceptions.RequestException:
                pass
            self.cquit(Status.DOWN, "Connection error", "Starpost is unavailable")

    def check(self):
        health.check(self)
        self.cquit(Status.OK)

    def put(self, flag_id, flag, vuln):
        scenario = SCENARIOS.get(vuln)
        if not scenario:
            self.cquit(Status.ERROR, "Unknown vuln", f"Unknown vuln {vuln}")
            return
        _public, private = scenario.put(self, flag)
        self.cquit(Status.OK, _public, json.dumps(private, separators=(",", ":")))

    def get(self, flag_id, flag, vuln):
        scenario = SCENARIOS.get(vuln)
        if not scenario:
            self.cquit(Status.ERROR, "Unknown vuln", f"Unknown vuln {vuln}")
            return
        try:
            state = json.loads(flag_id)
        except (TypeError, ValueError):
            self.cquit(Status.ERROR, "Invalid state", "Cannot decode flag ID")
            return
        expected_size = 2 if vuln == "3" else 3
        if not isinstance(state, list) or len(state) != expected_size:
            self.cquit(Status.ERROR, "Invalid state", f"Invalid state for vuln {vuln}")
            return
        scenario.get(self, state, flag)
        self.cquit(Status.OK)


if __name__ == "__main__":
    checker = Checker(sys.argv[2])
    try:
        checker.action(sys.argv[1], *sys.argv[3:])
    except checker.get_check_finished_exception():
        cquit(Status(checker.status), checker.public, checker.private)
    except Exception:
        cquit(Status.ERROR, "Checker error", traceback.format_exc(limit=8))
