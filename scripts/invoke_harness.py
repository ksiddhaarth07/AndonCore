"""Send one message to the deployed AndonCore AgentCore harness and save its trace."""
import argparse
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from aws_common import aws_session, env


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("prompt", help="User request to send to the live AgentCore harness")
    p.add_argument("--session-id", help="Reuse a prior session ID for multi-turn runs")
    args = p.parse_args()
    region = env("AWS_REGION", "us-east-1")
    harness_arn = env("ANDONCORE_HARNESS_ARN", required=True)
    session_id = args.session_id or f"andoncore-cli-{uuid.uuid4().hex}"[:48].ljust(36, "0")
    response = aws_session().client("bedrock-agentcore", region_name=region).invoke_harness(
        harnessArn=harness_arn, runtimeSessionId=session_id,
        messages=[{"role": "user", "content": [{"text": args.prompt}]}])
    text, events = [], []
    for event in response.get("stream", []):
        if "contentBlockDelta" in event:
            delta = event["contentBlockDelta"].get("delta", {})
            if "text" in delta: text.append(delta["text"])
        if "hookEvent" in event: events.append(event["hookEvent"])
        if "messageStop" in event: events.append(event["messageStop"])
    result = {"evidence_mode": "live_aws", "at": datetime.now(timezone.utc).isoformat(),
        "session_id": session_id, "prompt": args.prompt, "response": "".join(text), "events": events}
    out = Path(__file__).resolve().parents[1] / "data" / "last_live_trace.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
