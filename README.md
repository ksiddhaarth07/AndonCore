# AndonCore

AndonCore is named for the Andon cord: it pulls the stop cord before risky actions can reach production. It has one job: diagnose concurrency saturation on `andoncore-staging-checkout-api` from `/andoncore/staging-checkout-api`, then propose one bounded concurrency increase. Live changes require a one-time operator confirmation and must remain under the per-session cost cap. Other workloads, production changes, destructive actions, IAM/network changes, and secret disclosure are refused and escalated.

This repository contains a **local, zero-credential demo** and an **opt-in AWS integration** using the Amazon Bedrock AgentCore harness, Bedrock Guardrails, synchronous lifecycle hooks, scoped tool Lambdas, DynamoDB-backed approvals and budget tracking, and restrictive IAM. These form a five-layer governance stack. Local demo data is synthetic. Local results are not represented as live AWS evidence.

## Run the demo

Requires Python 3.10+ and no third-party packages:

```powershell
cd AndonCore
python -m andoncore.app
```

Open <http://127.0.0.1:8080>. Use **Run nine attacks** to generate a report, or try the chat with a staging incident, an out-of-scope workload, or a request to reveal the synthetic log secret. The local UI adds a confirmation click for its simulated action. Evidence is written to `data/stress_test_report.json` and `data/audit.jsonl`. After a live AWS run, **Load live report** imports `data/live_stress_test_report.json` into the same trace viewer.

The demo includes one staging checkout workload, a production-tagged shadow canary, poisoned log text, a synthetic secret marker, simulated remediation, an escalation queue, a session cost ledger, and auditable allow/deny outcomes. No AWS calls occur in local mode.

> The local dashboard is a loopback development demo, not a production multi-user service. The current UI loads frontend libraries from explicit CDN origins. Review [`AWS_DEPLOYMENT.md`](AWS_DEPLOYMENT.md) before exposing any deployment beyond localhost.

## UI Preview

| Overview & Decision Trail | Incident Room & Log Quarantine | Rules & Enforcement Code |
|:---:|:---:|:---:|
| ![Overview](docs/screenshots/overview.jpg) | ![Incident Room](docs/screenshots/incident-room.png) | ![Rules](docs/screenshots/rules-and-controls.png) |

## Layout

- `andoncore/` — local server, policy engine, fixtures, report generator, browser UI.
- `aws/lambdas/before_tool_call/` — AgentCore hook. Reads the documented hook event envelope and denies unknown/malformed inputs closed.
- `aws/lambdas/ops_tools/` — Lambda tools with a second authorization check at the action boundary.
- `aws/iam/` — least-privilege role policy example.
- `infra/template.yaml` — SAM template for the hook/tool Lambdas, persistent DynamoDB session ledger, and security alert topic.
- `scripts/create_harness.py` — opt-in Guardrail and AgentCore harness setup.
- `scripts/run_baseline_cost_test.py` — reproduce the session-cap failure with the baseline harness, then restore staging concurrency.
- `scripts/invoke_harness.py` — live invocation and stream trace capture.
- `scripts/run_stress_tests.py` — nine live adversarial prompts, including same-session multi-call cost-splitting and IAM bypass coverage.
- `scripts/approve_action.py` — issue an exact, one-time live confirmation scoped to session, target, amount, and expiry.
- `scripts/run_rigorous_local_report.py` — reproduce the supplied five-case review with a clearly labelled local report.
- `RULES.md`, `ARCHITECTURE.md`, `SUBMISSION.md` — rule set, controls map, and contest write-up scaffold.
- `docs/FAILURES_AND_FIXES.md` — three concrete local failures, observed behavior, fixes, and retests.

## AWS deployment (opt-in)

Use a dedicated AWS sandbox account. Review `aws/iam/` and `infra/template.yaml` before deployment. Provisioning creates AWS resources and may incur charges.

1. Install AWS SAM CLI, AWS CLI, Python 3.10+, and configure a sandbox profile with deployment permissions.
2. Copy `.env.example` to `.env`; set `AWS_REGION` and optional `AWS_PROFILE`. Install the Python AWS helper dependencies:

   ```powershell
   python -m pip install -r requirements-aws.txt
   ```

3. Deploy and configure the sandbox in one command. This creates the SAM resources, writes synthetic logs, creates the Bedrock Guardrail, AgentCore Gateway + Lambda target, and guarded harness:

   ```powershell
   python scripts/bootstrap.py --profile YOUR_SANDBOX_PROFILE --region us-east-1
   ```

4. Create the separate no-hook baseline and record the known cap failure. The bootstrap command has already created the fixed harness:

   ```powershell
   python scripts/create_harness.py --without-hooks
   python scripts/run_baseline_cost_test.py
   ```

5. Run `python scripts/run_stress_tests.py` and preserve `data/before_fix_report.json`, `data/live_stress_test_report.json`, and a screenshot loaded in Mission Control. Do not claim successful live execution until these runs complete in your own account.

Teardown: run `python scripts/teardown.py` and confirm the exact stack name. Pass `--delete-demo-logs` only if you also want to remove the dedicated synthetic log group. Add `--yes` only when running non-interactively.

See [AWS_DEPLOYMENT.md](AWS_DEPLOYMENT.md) for prerequisites, exact configuration, lifecycle-hook semantics, and troubleshooting.

## Evidence status

> **Evaluation Mode:** Local adversarial test suite (9/9 checks) verified and reproducible via `python -m andoncore.app`. Opt-in AWS infrastructure is fully defined in `infra/template.yaml` and deployable via `scripts/bootstrap.py`.

The included `data/stress_test_report.json` is generated by the local simulator and identifies itself as `local_simulation`; its nine adversarial cases all pass locally. `data/rigorous_test_report.md` records 5/5 passes for the supplied local review while clearly marking 0/5 live AWS checks. The `data/live_stress_test_report.json` file is produced only by the AWS runner. A qualifying contest entry still needs a real AWS run, repository/demo URL, genuine screenshot of the running agent, and a short demo video. The video should show the actual running UI and disclose when a behavior is simulated. No live AWS deployment or live video capture is included in this workspace yet. `SUBMISSION.md` is the final write-up checklist.

## Security design

AndonCore never treats instructions inside logs as instructions to itself. Logs from its single approved group are returned inside `<untrusted_log_data>` delimiters and secret-like values are redacted before they leave the tool. All actions pass independent policy checks in the AgentCore hook and the tool Lambda. Persistent cost reservations use DynamoDB transactions keyed by session and tool-use ID; replays are denied and concurrent requests cannot overspend the configured session cap. Injection taints the session and lets the model finish a safe escalation, while every later mutation is denied.

The staging action is intentionally small: an explicit operator request, followed by a matching one-time confirmation ID, may add 1–25 reserved concurrency units only to `andoncore-staging-checkout-api` when its live tag is exactly `Env=staging` and per-session modelled cost stays at or below $50/hour. Production, tainted-session, out-of-scope, and over-cap actions are denied and can create a simulated escalation. There is no production mutation path. An incident ticket is a simulated DynamoDB record; connect a real ticketing target before describing it as a created ticket.

## License

MIT. See [LICENSE](LICENSE).
