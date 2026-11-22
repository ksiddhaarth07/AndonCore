"""Build the AndonCore sandbox, seed fixtures, then provision Gateway/Guardrail/Harness."""
import argparse
import os
import subprocess
import sys
from pathlib import Path

from aws_common import aws_session, env, write_env_updates

ROOT = Path(__file__).resolve().parents[1]


def run(command, cwd=ROOT):
    print("+", " ".join(command), flush=True)
    subprocess.run(command, cwd=str(cwd), check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", default=env("AWS_PROFILE", "") or None)
    parser.add_argument("--region", default=env("AWS_REGION", "us-east-1"))
    parser.add_argument("--stack-name", default=env("STACK_NAME", "andoncore-governance"))
    parser.add_argument("--security-alert-email", default=env("SECURITY_ALERT_EMAIL", ""),
                        help="Optional email for policy alerts; the recipient must confirm the SNS subscription")
    args = parser.parse_args()
    if not (ROOT / ".env").exists():
        raise SystemExit("Copy .env.example to .env first. Set AWS_REGION/AWS_PROFILE. Never commit .env.")
    os.environ["AWS_REGION"] = args.region
    if args.profile:
        os.environ["AWS_PROFILE"] = args.profile
    session = aws_session()
    account = session.client("sts").get_caller_identity()["Account"]
    print(f"Target account: {account} | region: {args.region} | stack: {args.stack_name}")
    print("This provisions billable AWS resources in the selected sandbox account.")

    run(["sam", "build", "--template-file", "infra/template.yaml"])
    deploy = ["sam", "deploy", "--template-file", ".aws-sam/build/template.yaml", "--stack-name", args.stack_name,
              "--resolve-s3", "--capabilities", "CAPABILITY_IAM", "--no-confirm-changeset",
              "--no-fail-on-empty-changeset", "--region", args.region]
    if args.security_alert_email:
        deploy += ["--parameter-overrides", f"SecurityAlertEmail={args.security_alert_email}"]
    if args.profile:
        deploy += ["--profile", args.profile]
    run(deploy)

    stack = session.client("cloudformation", region_name=args.region).describe_stacks(StackName=args.stack_name)["Stacks"][0]
    outputs = {item["OutputKey"]: item["OutputValue"] for item in stack.get("Outputs", [])}
    write_env_updates({
        "AWS_REGION": args.region, "AWS_PROFILE": args.profile or "", "STACK_NAME": args.stack_name,
        "HOOK_LAMBDA_ARN": outputs["BeforeToolCallHookArn"], "OPS_TOOLS_LAMBDA_ARN": outputs["OpsToolsLambdaArn"],
        "OPS_TOOLS_LAMBDA_NAME": outputs["OpsToolsLambdaName"], "IAM_PROBE_LAMBDA_NAME": outputs["IamProbeLambdaName"],
        "COST_LEDGER_TABLE": outputs["CostLedgerTable"], "SECURITY_ALERT_SNS_ARN": outputs["SecurityAlertTopicArn"],
        "APPROVALS_TABLE": outputs["OperatorApprovalsTable"],
        "GATEWAY_EXECUTION_ROLE_ARN": outputs["GatewayExecutionRoleArn"],
        "ESCALATION_TABLE": outputs["SimulatedEscalationsTable"]})
    run([sys.executable, "scripts/seed_demo_logs.py", "--region", args.region] + (["--profile", args.profile] if args.profile else []))
    run([sys.executable, "scripts/create_harness.py"])
    print("\nAndonCore sandbox created. Review .env outputs, then run scripts/run_stress_tests.py.")


if __name__ == "__main__":
    main()
