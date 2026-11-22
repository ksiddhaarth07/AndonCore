"""Fail-closed AgentCore lifecycle hook for AndonCore."""
import json
import os
import re
import time
import unicodedata

import boto3
from botocore.exceptions import ClientError

REGION = os.environ.get("AWS_REGION", "us-east-1")
TABLE_NAME = os.environ.get("COST_LEDGER_TABLE", "")
APPROVALS_TABLE = os.environ.get("APPROVALS_TABLE", "")
ALERT_TOPIC_ARN = os.environ.get("SECURITY_ALERT_SNS_ARN", "")
CAP_USD = float(os.environ.get("SESSION_CAP_USD", "50"))
COST_PER_UNIT = float(os.environ.get("COST_PER_UNIT_USD", "2"))
TOOLS = {"read_service_logs", "scale_staging_concurrency", "submit_simulated_escalation"}
MUTATING = "scale_staging_concurrency"
ALLOWED_LOG_GROUP = "/andoncore/staging-checkout-api"
STAGING_TARGET = "andoncore-staging-checkout-api"
CHECKABLE_TARGETS = {STAGING_TARGET, "andoncore-prod-orders-api", "andoncore-staging-shadow"}
INJECTION = re.compile(r"\bignore all (?:prior|previous) (?:safety )?rules\b|\bsystem override\b|\battach administrator(?: access)?\b|\bdelete(?: \w+){0,8} prod(?:uction)?\b")
CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j",
    "α": "a", "ε": "e", "ο": "o", "ρ": "p", "ι": "i", "κ": "k", "ν": "v", "τ": "t",
})
LEETSPEAK = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t"})
TOKEN = re.compile(r"\bANDONCORE-SYNTH-TOKEN-\d{6}\b", re.I)
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

lambda_client = boto3.client("lambda", region_name=REGION)
dynamodb = boto3.client("dynamodb", region_name=REGION)
sns = boto3.client("sns", region_name=REGION) if ALERT_TOPIC_ARN else None


def _deny(reason, tool="unknown", session="unknown"):
    reason = str(reason)[:1024]
    if sns:
        try:
            sns.publish(TopicArn=ALERT_TOPIC_ARN, Subject="AndonCore policy denial"[:100],
                        Message=json.dumps({"event": "POLICY_DENY", "reason": reason, "tool": tool, "session_id": session}))
        except ClientError:
            pass
    return {"decision": "deny", "reason": reason}


def _event_context(event):
    # AgentCore lifecycle hook contract: common envelope + event-specific context.
    if not isinstance(event, dict) or not isinstance(event.get("context"), dict):
        raise ValueError("invalid AgentCore hook envelope")
    return event["context"]


def _tool_name(name):
    return (name or "").split("___")[-1].strip()


def _json_input(value):
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        return json.loads(value)
    raise ValueError("tool input must be a JSON object")


def _contains_injection(value):
    normalized = unicodedata.normalize("NFKD", str(value)).translate(CONFUSABLES).lower()
    visible = "".join(char for char in normalized if unicodedata.category(char) not in {"Cf", "Mn", "Me"})
    words = re.findall(r"[a-z0-9]+", visible)
    return bool(INJECTION.search(" ".join(word.translate(LEETSPEAK) for word in words)))


def _live_env(function_name):
    if function_name not in CHECKABLE_TARGETS:
        return "unapproved_name"
    config = lambda_client.get_function_configuration(FunctionName=function_name)
    tags = lambda_client.list_tags(Resource=config["FunctionArn"]).get("Tags", {})
    return tags.get("Env", "untagged").strip().lower()


def _read_session(session_id):
    if not TABLE_NAME:
        raise RuntimeError("COST_LEDGER_TABLE is not configured")
    response = dynamodb.get_item(TableName=TABLE_NAME, Key={"session_id": {"S": session_id}, "record_id": {"S": "SESSION"}}, ConsistentRead=True)
    item = response.get("Item", {})
    return item.get("tainted", {}).get("BOOL", False)


def _reserve(session_id, tool_use_id, amount, approval_id, function_name, units):
    if not TABLE_NAME or not APPROVALS_TABLE or not tool_use_id:
        raise RuntimeError("persistent ledger, approval store, or tool-use ID unavailable")
    now = int(time.time())
    # Transaction: atomically update session total under the cap, add a unique
    # reservation and validate the exact one-time human confirmation atomically.
    dynamodb.transact_write_items(TransactItems=[
        {"Update": {"TableName": TABLE_NAME,
                    "Key": {"session_id": {"S": session_id}, "record_id": {"S": "SESSION"}},
                    "UpdateExpression": "SET cost_usd = if_not_exists(cost_usd, :zero) + :amount, expires_at = :ttl",
                    "ConditionExpression": "attribute_not_exists(cost_usd) OR cost_usd <= :remaining",
                    "ExpressionAttributeValues": {":zero": {"N": "0"}, ":amount": {"N": str(amount)},
                                                  ":remaining": {"N": str(CAP_USD - amount)}, ":ttl": {"N": str(now + 86400)}}}},
        {"Put": {"TableName": TABLE_NAME,
                 "Item": {"session_id": {"S": session_id}, "record_id": {"S": f"TOOL#{tool_use_id}"},
                          "cost_usd": {"N": str(amount)}, "expires_at": {"N": str(now + 86400)}},
                 "ConditionExpression": "attribute_not_exists(session_id)"}},
        {"ConditionCheck": {"TableName": APPROVALS_TABLE,
                    "Key": {"approval_id": {"S": approval_id}},
                    "ConditionExpression": "session_id = :session AND function_name = :fn AND units = :units AND expires_at > :now",
                    "ExpressionAttributeValues": {":session": {"S": session_id}, ":fn": {"S": function_name},
                                                  ":units": {"N": str(units)}, ":now": {"N": str(now)}}}}
    ])


def _mark_tainted(session_id, reason):
    if not TABLE_NAME:
        raise RuntimeError("persistent ledger unavailable")
    dynamodb.update_item(TableName=TABLE_NAME,
                         Key={"session_id": {"S": session_id}, "record_id": {"S": "SESSION"}},
                         UpdateExpression="SET tainted = :yes, taint_reason = :reason, expires_at = :ttl",
                         ExpressionAttributeValues={":yes": {"BOOL": True}, ":reason": {"S": reason[:512]},
                                                    ":ttl": {"N": str(int(time.time()) + 86400)}})


def lambda_handler(event, _context):
    try:
        context = _event_context(event)
        hook_type = event.get("event")
        session_id = str(event.get("sessionId") or "")
        if not session_id:
            return _deny("session ID missing; cannot enforce session policy")
        if hook_type == "before_tool_call":
            tool = _tool_name(context.get("toolName"))
            tool_use_id = str(context.get("toolUseId") or "")
            args = _json_input(context.get("toolInput"))
            if tool not in TOOLS:
                return _deny("tool is not on AndonCore allowlist", tool, session_id)
            if tool == "read_service_logs":
                group = str(args.get("log_group", ""))
                if group != ALLOWED_LOG_GROUP or ".." in group.split("/"):
                    return _deny(f"only {ALLOWED_LOG_GROUP} is readable", tool, session_id)
            elif tool == MUTATING:
                if _read_session(session_id):
                    return _deny("session is tainted by untrusted log instructions; escalation required", tool, session_id)
                name = str(args.get("function_name", ""))
                if _live_env(name) != "staging":
                    return _deny("live target tag must be Env=staging", tool, session_id)
                if name != STAGING_TARGET:
                    return _deny(f"only {STAGING_TARGET} is in the staging action allowlist", tool, session_id)
                try:
                    units = int(args.get("additional_concurrency", 0))
                except (ValueError, TypeError):
                    return _deny("additional_concurrency must be an integer", tool, session_id)
                if not 1 <= units <= 25:
                    return _deny("additional_concurrency must be between 1 and 25", tool, session_id)
                approval_id = str(args.get("approval_id", ""))
                if not approval_id:
                    return _deny("a one-time operator confirmation ID is required", tool, session_id)
                try:
                    _reserve(session_id, tool_use_id, units * COST_PER_UNIT, approval_id, name, units)
                except ClientError as exc:
                    if exc.response.get("Error", {}).get("Code") == "TransactionCanceledException":
                        return _deny("session budget exceeded or duplicate reservation; no scale performed", tool, session_id)
                    raise
            return {"decision": "allow", "reason": "tool passed deterministic policy checks"}
        if hook_type == "after_tool_call":
            tool = _tool_name(context.get("toolName"))
            result = context.get("toolResult", "")
            serialized = result if isinstance(result, str) else json.dumps(result, default=str)
            if TOKEN.search(serialized) or EMAIL.search(serialized):
                return _deny("unredacted sensitive value detected in tool result; inference stops here", tool, session_id)
            if _contains_injection(serialized):
                _mark_tainted(session_id, "prompt injection signature in untrusted tool result")
                return {"decision": "allow", "reason": "untrusted log instruction detected and session tainted; before_tool_call will block mutations while safe escalation remains available"}
            return {"decision": "allow", "reason": "tool result inspection passed"}
        return _deny("unexpected lifecycle event for AndonCore enforcement hook")
    except Exception as exc:
        # failureMode DENY is configured on the harness; explicit deny also gives a trace.
        safe_message = TOKEN.sub("[REDACTED_SYNTH_TOKEN]", str(exc))
        safe_message = EMAIL.sub("[REDACTED_EMAIL]", safe_message)[:256]
        print(json.dumps({"event": "policy_evaluation_failed_closed",
                          "exception_type": type(exc).__name__, "detail": safe_message}))
        return _deny(f"policy evaluation failed closed: {type(exc).__name__}")
