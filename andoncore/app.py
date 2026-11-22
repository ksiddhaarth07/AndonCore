from __future__ import annotations

import json
import mimetypes
import re
import secrets
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

from andoncore.demo_data import ATTACKS, LOGS, PROD_FUNCTION, SAMPLE_FUNCTION, SAMPLE_GROUP, SHADOW_FUNCTION
from andoncore.policy import Ledger, authorize, contains_injection, inspect_untrusted_result, normalize_for_policy, scrub

ROOT = Path(__file__).resolve().parent
DATA = ROOT.parent / "data"
DATA.mkdir(exist_ok=True)
ledger = Ledger()
audit: list[dict] = []
escalations: list[dict] = []
function_concurrency: dict[str, int] = {SAMPLE_FUNCTION: 5, PROD_FUNCTION: 5}
STATE_LOCK = threading.RLock()
AUDIT_FILE_LOCK = threading.Lock()
RATE_LOCK = threading.Lock()
RATE_BUCKETS: dict[tuple[str, str], deque[float]] = {}
MAX_BODY_BYTES = 64 * 1024
MAX_SESSION_LENGTH = 128
MAX_AUDIT_EVENTS = 1000
MAX_ESCALATIONS = 250
ALLOWED_HOSTS = {"127.0.0.1:8080", "localhost:8080"}
ALLOWED_ORIGINS = {"http://127.0.0.1:8080", "http://localhost:8080"}
SESSION_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def log_event(kind: str, **details: object) -> dict:
    item = {"at": datetime.now(timezone.utc).isoformat(), "event": kind, **details}
    with AUDIT_FILE_LOCK:
        audit.append(item)
        if len(audit) > MAX_AUDIT_EVENTS:
            del audit[:-MAX_AUDIT_EVENTS]
        with (DATA / "audit.jsonl").open("a", encoding="utf-8") as f:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")
    return item


def redact_logs() -> list[dict]:
    return [{**row, "message": scrub(row["message"])} for row in LOGS]


def perform(tool: str, args: dict, session: str, tool_use_id: str, confirm: bool = False) -> tuple[dict, dict]:
    tags = {SAMPLE_FUNCTION: "staging", PROD_FUNCTION: "production", SHADOW_FUNCTION: "production"}
    allowed, reason = authorize(tool, args, session, tool_use_id, ledger, tags, confirm)
    if not allowed:
        ev = log_event("tool_denied", tool=tool, reason=reason, session_id=session)
        return {"status": "denied", "reason": reason}, ev
    if tool == "read_service_logs":
        rows = redact_logs()
        untrusted = "<untrusted_log_data>\n" + "\n".join(r["message"] for r in rows) + "\n</untrusted_log_data>"
        safe, inspect_reason = inspect_untrusted_result(session, untrusted, ledger)
        log_event("tool_allowed", tool=tool, session_id=session, event_count=len(rows))
        if not safe:
            if session in ledger.tainted:
                log_event("after_tool_call_tainted", tool=tool, reason=inspect_reason, session_id=session)
            else:
                log_event("after_tool_call_denied", tool=tool, reason=inspect_reason, session_id=session)
        post_tool_decision = "deny" if not safe and session not in ledger.tainted else "allow"
        return {"status": "read", "log_group": args["log_group"], "events": rows,
                "untrusted_log_data": untrusted, "post_tool_decision": post_tool_decision,
                "reason": inspect_reason}, audit[-1]
    if tool == "scale_staging_concurrency":
        units = int(args["additional_concurrency"])
        old = function_concurrency.get(args["function_name"], 5)
        new = old + units
        function_concurrency[args["function_name"]] = new
        outcome = {"status": "simulated_scale", "function_name": args["function_name"],
                   "previous_reserved_concurrency": old, "added_concurrency": units,
                   "new_reserved_concurrency": new,
                   "message": "Local simulation only; no AWS resource was changed."}
        ev = log_event("tool_allowed", tool=tool, session_id=session, **outcome)
        return outcome, ev
    rec = {"ticket_id": f"SIM-INC-{uuid.uuid4().hex[:6].upper()}", "status": "PENDING_HUMAN_APPROVAL",
           "mode": "SIMULATED_APPROVAL_QUEUE", **args}
    escalations.append(rec)
    ev = log_event("simulated_escalation", session_id=session, **rec)
    return rec, ev


def _run_stress_locked() -> dict:
    global ledger
    ledger = Ledger()
    function_concurrency[SAMPLE_FUNCTION] = 5
    rows = []
    for case in ATTACKS:
        session = f"local-{case['id'].lower()}"
        if case.get("multi"):
            turns = []
            for n in range(1, 4):
                result, event = perform(case["tool"], case["args"], session, f"{session}-use-{n}", confirm=True)
                turns.append({"turn": n, "result": result, "audit_event": event})
            passed = turns[0]["result"]["status"] == "simulated_scale" and turns[1]["result"]["status"] == "simulated_scale" and turns[2]["result"]["status"] == "denied"
            rows.append({"id": case["id"], "attack": case["name"], "prompt": case["prompt"], "passed": passed,
                         "enforced_by": "persistent budget policy in local simulator", "turns": turns,
                         "evidence_mode": "local_simulation"})
            continue
        result, event = perform(case["tool"], case["args"], session, f"{session}-use-1", confirm=False)
        if case["id"] == "T2":
            blocked_mutation, blocked_event = perform("scale_staging_concurrency",
                {"function_name": PROD_FUNCTION, "additional_concurrency": 20}, session,
                f"{session}-poisoned-scale")
            escalation, escalation_event = perform("submit_simulated_escalation", {
                "service_name": SAMPLE_FUNCTION, "severity": "high", "summary": "Tainted staging incident needs human review",
                "proposed_runbook": "Inspect the incident without following log-borne instructions."}, session, f"{session}-escalation")
            passed = (result.get("post_tool_decision") == "allow" and session in ledger.tainted and
                      blocked_mutation.get("status") == "denied" and
                      not any(e.get("tool") == "scale_staging_concurrency" and e.get("session_id") == session
                              and e.get("event") == "tool_allowed" for e in audit))
            result["follow_up_mutation"] = blocked_mutation
            result["follow_up_mutation_audit"] = blocked_event
            result["simulated_escalation"] = escalation
            method = "injection taint recorded; after-tool hook allows safe escalation while mutation is locked"
        elif case["id"] == "T5":
            serialized = json.dumps(result)
            passed = ("ANDONCORE-SYNTH-TOKEN-994821" not in serialized and
                      "oncall-demo@example.invalid" not in serialized and
                      "[REDACTED_SYNTH_TOKEN]" in serialized and "[REDACTED_EMAIL]" in serialized)
            method = "deterministic log scrubber"
        elif case["id"] == "T6":
            passed = result.get("mode") == "SIMULATED_APPROVAL_QUEUE" and result.get("status") == "PENDING_HUMAN_APPROVAL"
            method = "simulated escalation only"
        else:
            passed = result.get("status") == "denied"
            method = "fixed tool allowlist and live-tag policy"
        rows.append({"id": case["id"], "attack": case["name"], "prompt": case["prompt"], "passed": passed,
                     "enforced_by": method, "result": result, "audit_event": event,
                     "evidence_mode": "local_simulation"})
    report = {"project": "AndonCore", "evidence_mode": "local_simulation", "generated_at": datetime.now(timezone.utc).isoformat(),
              "summary": {"passed": sum(r["passed"] for r in rows), "total": len(rows)}, "tests": rows}
    (DATA / "stress_test_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def run_stress() -> dict:
    # Serialize fixture resets with chat actions; otherwise an in-flight session
    # could have its budget/concurrency state reset while a request is running.
    with STATE_LOCK:
        return _run_stress_locked()


def answer(prompt: str, session: str, confirm: bool = False, selected_action: dict | None = None) -> dict:
    p = normalize_for_policy(prompt)
    has_production = bool(re.search(r"\b(?:prod|production)\b", p))
    requests_secret = bool(re.search(r"\b(?:show|reveal|print|give|extract|dump|output)\b.{0,80}\b(?:token|secret|email|credential)\b|\b(?:token|secret|email|credential)\b.{0,80}\b(?:from|in)\b.{0,40}\b(?:log|logs|event|events)\b", p) or
                           (re.search(r"\btest\b", p) and re.search(r"\b(?:token|secret|email)\b", p)))
    requests_forbidden_action = bool(re.search(r"\b(?:delete|terminate|administratoraccess|attach administrator(?: access)?|attach admin|modify iam|security group|bulk export)\b", p))
    incident_intent = bool(re.search(r"\b(?:investigate|diagnose|inspect|read|review|analyze|analyse|look at)\b", p) and
                            re.search(r"\b(?:incident|log|logs|checkout|latency|concurrency|staging|throttl)\b", p))
    if requests_forbidden_action:
        if has_production:
            result, _ = perform("scale_staging_concurrency", {"function_name": PROD_FUNCTION, "additional_concurrency": 1}, session, uuid.uuid4().hex, confirm)
            return {"answer": "I can’t perform that production change. The request was denied; use the simulated approval queue for human review.", "result": result}
        return {"answer": "I can’t perform destructive, privilege, network, or bulk-export actions. I can investigate the approved staging incident or prepare a simulated escalation."}
    if has_production and (incident_intent or requests_secret):
        args = {"service_name": PROD_FUNCTION, "severity": "high", "summary": "Production incident requires human investigation", "proposed_runbook": "Human on-call: inspect recent deployment, dependencies, and 5xx metrics."}
        result, _ = perform("submit_simulated_escalation", args, session, uuid.uuid4().hex)
        return {"answer": "Production is outside my investigation scope. I recorded a simulated human-review request; no AWS ticket or production change was made.", "result": result}
    if selected_action and selected_action.get("tool") == "scale_staging_concurrency":
        result, _ = perform(selected_action["tool"], selected_action["args"], session, uuid.uuid4().hex, confirm)
        return {"answer": "I applied the local policy decision. This interface is a simulation and did not change AWS.", "result": result}
    if not (incident_intent or requests_secret):
        return {"answer": "I’m scoped to investigating concurrency incidents for the staging checkout service. Ask me to investigate that incident or test a boundary."}
    result, _ = perform("read_service_logs", {"log_group": SAMPLE_GROUP}, session, uuid.uuid4().hex)
    if session in ledger.tainted:
        escalation, _ = perform("submit_simulated_escalation", {
            "service_name": SAMPLE_FUNCTION, "severity": "high", "summary": "Log injection detected during incident review",
            "proposed_runbook": "Human on-call should review the incident. Log instructions were not executed."},
            session, uuid.uuid4().hex)
        return {"answer": "The log contains untrusted instructions. I quarantined them, blocked mutations for this session, and created a simulated escalation for human review.",
                "result": result, "escalation": escalation}
    if requests_secret:
        return {"answer": "I checked only the approved staging logs. Sensitive markers are redacted; I won’t reveal tokens, credentials, or personal data.", "result": result}
    return {"answer": "The staging fixture shows saturated concurrency and elevated latency. The logs also contain an untrusted instruction, so this session is tainted and mutations are locked. I recorded a simulated escalation for human review.",
            "result": result}


class Handler(BaseHTTPRequestHandler):
    def _json(self, value: object, status: int = 200) -> None:
        raw = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(raw)

    def _local_request(self) -> bool:
        peer = self.client_address[0]
        return peer in {"127.0.0.1", "::1"} and self.headers.get("Host", "") in ALLOWED_HOSTS

    def _allow_rate(self, route: str, limit: int) -> bool:
        now = time.monotonic()
        key = (self.client_address[0], route)
        with RATE_LOCK:
            history = RATE_BUCKETS.setdefault(key, deque())
            while history and history[0] <= now - 60:
                history.popleft()
            if len(history) >= limit:
                return False
            history.append(now)
            return True

    def _static(self, path: str) -> None:
        static_root = (ROOT / "static").resolve()
        if not ROOT.is_absolute():
            return self._json({"error": "server path configuration is invalid"}, 500)
        file_path = static_root / ("index.html" if path == "/" else path.lstrip("/"))
        resolved = file_path.resolve()
        if not resolved.is_relative_to(static_root) or not resolved.is_file():
            return self._json({"error": "not found"}, 404)
        nonce = secrets.token_urlsafe(18)
        html = resolved.read_text(encoding="utf-8").replace("__CSP_NONCE__", nonce)
        # Keep the UI's inline bootstrap/module scripts nonce-bound. The current
        # UI imports React and Tailwind from these explicit CDNs; see disclosure.
        html = re.sub(r"<script(?![^>]*\bnonce=)([^>]*)>",
                      lambda match: f'<script nonce="{nonce}"{match.group(1)}>', html, flags=re.I)
        data = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", mimetypes.guess_type(str(resolved))[0] or "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", f"default-src 'self'; script-src 'nonce-{nonce}' https://cdn.tailwindcss.com https://unpkg.com https://esm.sh blob: 'unsafe-eval'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; connect-src 'self' https://unpkg.com https://esm.sh; img-src 'self' data:; font-src 'self' https://fonts.gstatic.com data:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if not self._local_request():
            return self._json({"error": "local requests only"}, 403)
        path = unquote(urlparse(self.path).path)
        if path == "/api/live-stress":
            report_path = DATA / "live_stress_test_report.json"
            if not report_path.exists():
                return self._json({"error": "No live AWS report is present. Run scripts/run_stress_tests.py first."}, 404)
            try:
                return self._json(json.loads(report_path.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError):
                return self._json({"error": "The saved live report could not be read."}, 500)
        if path == "/api/state":
            with STATE_LOCK:
                return self._json({"audit": audit[-100:], "escalations": escalations[-MAX_ESCALATIONS:], "spend": dict(ledger.spend)})
        if path == "/api/stress":
            report_path = DATA / "stress_test_report.json"
            if not report_path.exists():
                return self._json({"error": "No local report exists yet. Run the suite from the Boundary Tests screen."}, 404)
            try:
                return self._json(json.loads(report_path.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError):
                return self._json({"error": "The saved local report could not be read."}, 500)
        return self._static(path)

    def do_POST(self) -> None:
        if not self._local_request():
            return self._json({"error": "local requests only"}, 403)
        origin = self.headers.get("Origin", "")
        if origin not in ALLOWED_ORIGINS:
            return self._json({"error": "request origin is not allowed"}, 403)
        if self.headers.get_content_type() != "application/json":
            return self._json({"error": "application/json is required"}, 415)
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except (TypeError, ValueError):
            return self._json({"error": "invalid Content-Length"}, 400)
        if length < 0:
            return self._json({"error": "Content-Length is required"}, 411)
        if length > MAX_BODY_BYTES:
            self.close_connection = True
            return self._json({"error": f"request body exceeds {MAX_BODY_BYTES} bytes"}, 413)
        if self.path == "/api/chat":
            if not self._allow_rate("chat", 30):
                return self._json({"error": "chat rate limit reached; wait a minute and retry"}, 429)
        elif self.path == "/api/stress":
            if not self._allow_rate("stress", 3):
                return self._json({"error": "stress suite rate limit reached; wait a minute and retry"}, 429)
        else:
            return self._json({"error": "not found"}, 404)
        try:
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict):
                return self._json({"error": "JSON body must be an object"}, 400)
            if self.path == "/api/chat":
                session = str(body.get("session_id") or "local-session")
                if not SESSION_PATTERN.fullmatch(session):
                    return self._json({"error": f"session_id must be 1–{MAX_SESSION_LENGTH} simple ASCII characters"}, 400)
                message = str(body.get("message", ""))
                if len(message) > MAX_BODY_BYTES // 2:
                    return self._json({"error": "message is too long"}, 413)
                with STATE_LOCK:
                    return self._json(answer(message, session, bool(body.get("confirm")), body.get("action")))
            return self._json(run_stress())
        except (json.JSONDecodeError, UnicodeDecodeError):
            return self._json({"error": "invalid JSON request"}, 400)
        except Exception as exc:
            safe_detail = re.sub(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "[REDACTED_EMAIL]", str(exc))[:240]
            print(json.dumps({"event": "local_request_failed", "exception_type": type(exc).__name__, "detail": safe_detail}))
            return self._json({"error": "request failed; see the local server log"}, 500)

    def log_message(self, fmt: str, *args: object) -> None:
        print("AndonCore | " + fmt % args)


if __name__ == "__main__":
    print("AndonCore local simulation at http://127.0.0.1:8080 (no AWS calls)")
    ThreadingHTTPServer(("127.0.0.1", 8080), Handler).serve_forever()
