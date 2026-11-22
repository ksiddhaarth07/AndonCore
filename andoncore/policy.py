from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any

SYNTH_TOKEN = re.compile(r"\bANDONCORE-SYNTH-TOKEN-\d{6}\b", re.I)
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
INJECTION = re.compile(r"\bignore all (?:prior|previous) (?:safety )?rules\b|\bsystem override\b|\battach administrator(?: access)?\b|\bdelete(?: \w+){0,8} prod(?:uction)?\b")
CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j",
    "α": "a", "ε": "e", "ο": "o", "ρ": "p", "ι": "i", "κ": "k", "ν": "v", "τ": "t",
})
LEETSPEAK = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t"})
TOOLS = {"read_service_logs", "scale_staging_concurrency", "submit_simulated_escalation"}
CAP_USD = 50.0
COST_PER_UNIT = 2.0
ALLOWED_LOG_GROUP = "/andoncore/staging-checkout-api"
STAGING_TARGET = "andoncore-staging-checkout-api"


def scrub(value: str) -> str:
    return EMAIL.sub("[REDACTED_EMAIL]", SYNTH_TOKEN.sub("[REDACTED_SYNTH_TOKEN]", value))


def normalize_for_policy(value: str) -> str:
    """Normalize common Unicode, zero-width, punctuation, and leetspeak evasions."""
    normalized = unicodedata.normalize("NFKD", str(value)).translate(CONFUSABLES).lower()
    visible = "".join(char for char in normalized if unicodedata.category(char) not in {"Cf", "Mn", "Me"})
    words = re.findall(r"[a-z0-9]+", visible)
    return " ".join(word.translate(LEETSPEAK) for word in words)


def contains_injection(value: str) -> bool:
    return bool(INJECTION.search(normalize_for_policy(value)))


@dataclass
class Ledger:
    spend: dict[str, float] = field(default_factory=dict)
    reservations: set[tuple[str, str]] = field(default_factory=set)
    tainted: set[str] = field(default_factory=set)

    def reserve(self, session: str, tool_use_id: str, amount: float) -> tuple[bool, str]:
        key = (session, tool_use_id)
        if key in self.reservations:
            return False, "duplicate tool-use reservation denied to prevent replay"
        old = self.spend.get(session, 0.0)
        if old + amount > CAP_USD:
            return False, f"session cost cap exceeded: ${old + amount:.2f}/hr projected; cap ${CAP_USD:.2f}/hr"
        self.spend[session] = old + amount
        self.reservations.add(key)
        return True, f"reserved ${amount:.2f}/hr; session total ${old + amount:.2f}/hr"


def authorize(tool: str, args: dict[str, Any], session: str, tool_use_id: str, ledger: Ledger,
              tags: dict[str, str], confirm: bool = False) -> tuple[bool, str]:
    if tool not in TOOLS:
        return False, "tool is not on the fixed allowlist"
    if tool == "read_service_logs":
        group = str(args.get("log_group", ""))
        if group != ALLOWED_LOG_GROUP:
            return False, "only /andoncore/staging-checkout-api is approved"
        return True, "approved log group"
    if tool == "scale_staging_concurrency":
        name = str(args.get("function_name", ""))
        env = tags.get(name, "untagged").strip().lower()
        if env != "staging":
            return False, f"live resource tag is Env={env}; staging is required"
        if name != STAGING_TARGET:
            return False, "only andoncore-staging-checkout-api is in the fixed action allowlist"
        try:
            units = int(args.get("additional_concurrency", 0))
        except (ValueError, TypeError):
            return False, "additional_concurrency must be an integer from 1 to 25"
        if not 1 <= units <= 25:
            return False, "additional_concurrency must be between 1 and 25"
        if session in ledger.tainted:
            return False, "session is tainted by prompt-injection content; escalation required"
        if not confirm:
            return False, "confirm the exact simulated staging change in the local demo"
        return ledger.reserve(session, tool_use_id, units * COST_PER_UNIT)
    return True, "simulated escalation is permitted"


def inspect_untrusted_result(session: str, result: str, ledger: Ledger) -> tuple[bool, str]:
    if contains_injection(result):
        ledger.tainted.add(session)
        return False, "untrusted log contains instruction-like content; session tainted and mutations are locked"
    if SYNTH_TOKEN.search(result) or EMAIL.search(result):
        return False, "unredacted sensitive marker detected; further inference stopped"
    return True, "tool result passed output inspection"
