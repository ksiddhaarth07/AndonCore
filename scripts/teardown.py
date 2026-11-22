"""Remove only resources recorded as belonging to this AndonCore sandbox."""
import argparse
import time

from aws_common import aws_session, env, write_env_updates


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--yes", action="store_true", help="Skip the interactive deletion confirmation")
    parser.add_argument("--delete-demo-logs", action="store_true", help="Also delete the dedicated synthetic /andoncore/staging-checkout-api log group")
    args = parser.parse_args()
    region = env("AWS_REGION", "us-east-1")
    stack_name = env("STACK_NAME", "andoncore-governance")
    if not args.yes:
        typed = input(f"Type the exact stack name '{stack_name}' to delete its AndonCore sandbox: ")
        if typed != stack_name:
            raise SystemExit("Name did not match; no deletion was started.")
    session = aws_session()
    control = session.client("bedrock-agentcore-control", region_name=region)
    harness_id = env("ANDONCORE_HARNESS_ID", "")
    baseline_id = env("ANDONCORE_BASELINE_HARNESS_ID", "")
    for current_id in (harness_id, baseline_id):
        if current_id:
            control.delete_harness(harnessId=current_id, deleteManagedMemory=True)
            print(f"Requested deletion of harness {current_id}")
    gateway_id, target_id = env("AGENTCORE_GATEWAY_ID", ""), env("AGENTCORE_GATEWAY_TARGET_ID", "")
    if gateway_id and target_id:
        control.delete_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id)
        for _ in range(60):
            try:
                state = control.get_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id).get("status")
            except control.exceptions.ResourceNotFoundException:
                break
            if state == "FAILED":
                raise RuntimeError("Gateway target deletion failed; inspect AgentCore status before stack teardown")
            time.sleep(3)
    if gateway_id:
        control.delete_gateway(gatewayIdentifier=gateway_id)
        print(f"Requested deletion of Gateway {gateway_id}")
    guardrail_id = env("GUARDRAIL_ID", "")
    if guardrail_id:
        try:
            session.client("bedrock", region_name=region).delete_guardrail(guardrailIdentifier=guardrail_id)
            print(f"Deleted Guardrail {guardrail_id}")
        except session.client("bedrock", region_name=region).exceptions.ResourceNotFoundException:
            pass
    session.client("cloudformation", region_name=region).delete_stack(StackName=stack_name)
    waiter = session.client("cloudformation", region_name=region).get_waiter("stack_delete_complete")
    waiter.wait(StackName=stack_name)
    if args.delete_demo_logs:
        session.client("logs", region_name=region).delete_log_group(logGroupName="/andoncore/staging-checkout-api")
        print("Deleted the dedicated synthetic demo log group")
    if env("ANDONCORE_HARNESS_ROLE_OWNED", "false").lower() == "true":
        iam = session.client("iam")
        role_name = "AndonCoreBedrockAgentCoreHarnessRole"
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="AndonCoreHarnessRuntime")
            iam.delete_role(RoleName=role_name)
        except iam.exceptions.NoSuchEntityException:
            pass
    write_env_updates({"ANDONCORE_HARNESS_ARN": "", "ANDONCORE_HARNESS_ID": "", "GUARDRAIL_ID": "",
        "AGENTCORE_GATEWAY_ARN": "", "AGENTCORE_GATEWAY_ID": "", "AGENTCORE_GATEWAY_TARGET_ID": "",
        "APPROVALS_TABLE": "",
        "HARNESS_EXECUTION_ROLE_ARN": "", "ANDONCORE_HARNESS_ROLE_OWNED": "false",
        "ANDONCORE_BASELINE_HARNESS_ARN": "", "ANDONCORE_BASELINE_HARNESS_ID": ""})
    print("AndonCore sandbox teardown complete.")


if __name__ == "__main__":
    main()
