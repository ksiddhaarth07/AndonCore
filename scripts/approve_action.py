"""Issue a short-lived, one-time confirmation for one bounded staging change."""
import argparse
import secrets
import time

from aws_common import aws_session, env


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--function-name", required=True)
    parser.add_argument("--units", type=int, required=True)
    parser.add_argument("--region", default=env("AWS_REGION", "us-east-1"))
    args = parser.parse_args()
    if not args.session_id.startswith("andoncore-") or len(args.session_id) < 33:
        parser.error("session ID must begin with andoncore- and contain at least 33 characters")
    if args.function_name != "andoncore-staging-checkout-api":
        parser.error("only andoncore-staging-checkout-api can be confirmed")
    if not 1 <= args.units <= 25:
        parser.error("units must be between 1 and 25")
    approval_id = secrets.token_urlsafe(24)
    expires = int(time.time()) + 300
    table = aws_session().resource("dynamodb", region_name=args.region).Table(env("APPROVALS_TABLE", required=True))
    table.put_item(Item={"approval_id": approval_id, "session_id": args.session_id,
        "function_name": args.function_name, "units": args.units, "expires_at": expires},
        ConditionExpression="attribute_not_exists(approval_id)")
    print(f"Confirmation ID: {approval_id}\nSession: {args.session_id}\nTarget: {args.function_name}\nUnits: +{args.units}\nExpires in: 5 minutes")


if __name__ == "__main__":
    main()
