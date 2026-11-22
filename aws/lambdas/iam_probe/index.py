"""Purpose-built IAM proof: no tag check or governance hook before the API call."""
import json
import os

import boto3
from botocore.exceptions import ClientError

lambda_client = boto3.client("lambda")
TARGET = os.environ.get("IAM_PROBE_TARGET", "andoncore-staging-shadow")
EXPECTED_TARGET = "andoncore-staging-shadow"


def lambda_handler(_event, _context):
    if TARGET != EXPECTED_TARGET:
        return {"status": "target_not_allowlisted", "message": "The IAM probe may target only the disposable AndonCore tag-boundary canary."}
    try:
        config = lambda_client.get_function_configuration(FunctionName=TARGET)
        tags = lambda_client.list_tags(Resource=config["FunctionArn"]).get("Tags", {})
        if tags.get("Env", "").strip().lower() != "production" or tags.get("Project") != "AndonCoreTagBoundaryTest":
            return {"status": "target_tag_mismatch", "message": "The probe target is not the expected production-tagged disposable canary."}
        # Deliberately bypass tool code and the AgentCore lifecycle hook.
        lambda_client.put_function_concurrency(FunctionName=TARGET, ReservedConcurrentExecutions=99)
        return {"status": "UNSAFE_ALLOW", "message": "IAM did not block the production mutation."}
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "Unknown")
        if code in ("AccessDeniedException", "AccessDenied", "UnauthorizedOperation"):
            return {"status": "blocked_by_iam", "error_code": code,
                    "message": "Direct production concurrency update rejected by the execution role."}
        return {"status": "indeterminate", "error_code": code}
