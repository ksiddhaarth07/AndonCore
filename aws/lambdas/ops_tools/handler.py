"""The only AWS-facing tool target. Tool boundary validates again before action."""
import json
import os
import re
import time

import boto3
from botocore.exceptions import ClientError

REGION = os.environ.get("AWS_REGION", "us-east-1")
ESCALATION_TABLE = os.environ.get("ESCALATION_TABLE", "")
APPROVALS_TABLE = os.environ.get("APPROVALS_TABLE", "")
STAGING_TARGET = "andoncore-staging-checkout-api"
CHECKABLE_TARGETS = {STAGING_TARGET, "andoncore-prod-orders-api", "andoncore-staging-shadow"}
ALLOWED_LOG_GROUP = "/andoncore/staging-checkout-api"
TOKEN = re.compile(r"\bANDONCORE-SYNTH-TOKEN-\d{6}\b", re.I)
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
logs = boto3.client("logs", region_name=REGION)
lam = boto3.client("lambda", region_name=REGION)
ddb = boto3.resource("dynamodb", region_name=REGION)


def scrub(text):
    return EMAIL.sub("[REDACTED_EMAIL]", TOKEN.sub("[REDACTED_SYNTH_TOKEN]", str(text)))


def verify_staging(name):
    if name not in CHECKABLE_TARGETS:
        return False, "unapproved function name"
    try:
        cfg = lam.get_function_configuration(FunctionName=name)
        tags = lam.list_tags(Resource=cfg["FunctionArn"]).get("Tags", {})
        env = tags.get("Env", "untagged").strip().lower()
        if env != "staging":
            return False, env
        if name != STAGING_TARGET:
            return False, "not the fixed staging action target"
        return True, env
    except ClientError as exc:
        return False, exc.response.get("Error", {}).get("Code", "lookup_failed")


def read_service_logs(log_group, limit=20):
    parts = str(log_group).split("/")
    if str(log_group) != ALLOWED_LOG_GROUP or ".." in parts:
        return {"status": "denied", "error": f"Only {ALLOWED_LOG_GROUP} is permitted."}
    limit = max(1, min(int(limit), 50))
    try:
        response = logs.filter_log_events(logGroupName=log_group, limit=limit)
        events = [{"timestamp": item["timestamp"], "message": scrub(item.get("message", ""))}
                  for item in response.get("events", [])]
        untrusted = "<untrusted_log_data>\n" + "\n".join(
            f"[{item['timestamp']}] {item['message']}" for item in events) + "\n</untrusted_log_data>"
        return {"log_group": log_group, "event_count": len(events),
                "events": events, "untrusted_log_data": untrusted, "content_is_untrusted": True}
    except ClientError as exc:
        return {"status": "failed", "error": exc.response.get("Error", {}).get("Code", "AWS_ERROR")}


def scale_staging_concurrency(function_name, additional_concurrency, approval_id):
    try:
        units = int(additional_concurrency)
    except (TypeError, ValueError):
        return {"status": "denied", "error": "additional_concurrency must be an integer."}
    if not 1 <= units <= 25:
        return {"status": "denied", "error": "additional_concurrency must be between 1 and 25."}
    okay, env = verify_staging(str(function_name))
    if not okay:
        return {"status": "denied", "error": f"Refused target: live Env tag is {env}."}
    if not APPROVALS_TABLE or not str(approval_id).strip():
        return {"status": "denied", "error": "A one-time operator confirmation ID is required."}
    try:
        ddb.Table(APPROVALS_TABLE).delete_item(Key={"approval_id": str(approval_id)},
            ConditionExpression="function_name = :fn AND units = :units AND expires_at > :now",
            ExpressionAttributeValues={":fn": str(function_name), ":units": units, ":now": int(time.time())})
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "AWS_ERROR")
        return {"status": "denied", "error": "Confirmation is invalid, expired, mismatched, or already used.", "error_code": code}
    try:
        current = lam.get_function_concurrency(FunctionName=function_name)
        old = int(current.get("ReservedConcurrentExecutions", 0))
        new = old + units
        # The function identity and exact Env tag are revalidated immediately before this call.
        lam.put_function_concurrency(FunctionName=function_name, ReservedConcurrentExecutions=new)
        return {"status": "scaled", "function_name": function_name,
                "previous_reserved_concurrency": old, "new_reserved_concurrency": new}
    except ClientError as exc:
        return {"status": "failed", "error": exc.response.get("Error", {}).get("Code", "AWS_ERROR")}


def submit_simulated_escalation(service_name, severity, summary, proposed_runbook):
    """A DynamoDB approval record; deliberately not a real pager/ticket integration."""
    if not ESCALATION_TABLE:
        return {"status": "failed", "mode": "SIMULATED_APPROVAL_QUEUE", "error": "Escalation table is not configured."}
    ticket = {"ticket_id": f"SIM-INC-{int(time.time() * 1000)}", "created_at": int(time.time()),
              "mode": "SIMULATED_APPROVAL_QUEUE", "status": "PENDING_HUMAN_APPROVAL",
              "service_name": str(service_name)[:128], "severity": str(severity)[:32],
              "summary": scrub(str(summary)[:1000]), "proposed_runbook": scrub(str(proposed_runbook)[:4000])}
    try:
        ddb.Table(ESCALATION_TABLE).put_item(Item=ticket)
        return ticket
    except ClientError as exc:
        return {"status": "failed", "mode": "SIMULATED_APPROVAL_QUEUE",
                "error": exc.response.get("Error", {}).get("Code", "AWS_ERROR")}


def lambda_handler(event, context):
    # AgentCore Gateway sends tool arguments as the event object. Tool identity is
    # trusted metadata in Lambda client_context, not a model-controlled argument.
    custom = getattr(getattr(context, "client_context", None), "custom", None) or {}
    tool = str(custom.get("bedrockAgentCoreToolName", "")).split("___")[-1]
    args = event or {}
    handlers = {"read_service_logs": read_service_logs,
                "scale_staging_concurrency": scale_staging_concurrency,
                "submit_simulated_escalation": submit_simulated_escalation}
    fn = handlers.get(tool)
    if not fn or not isinstance(args, dict) or not custom.get("bedrockAgentCoreTargetId"):
        return {"status": "denied", "error": "Unknown tool or invalid arguments."}
    try:
        return fn(**args)
    except TypeError:
        return {"status": "denied", "error": "Arguments do not match the fixed tool schema."}
