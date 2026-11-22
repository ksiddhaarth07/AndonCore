# AndonCore sandbox operations

## Restore the staging test fixture

The live baseline and T4 scenarios temporarily change reserved concurrency on exactly `andoncore-staging-checkout-api`. The runner attempts to restore the value it observed before each scenario in a `finally` block. Check the report and runner output for `previous_reserved_concurrency` and the restore result.

If restoration failed, use the same AWS profile and region as the run. First inspect the current value and live tags; stop if the target name or `Env=staging` tag does not match:

```powershell
$profile = "YOUR_SANDBOX_PROFILE"
$region = "us-east-1"
$function = "andoncore-staging-checkout-api"
aws lambda get-function --function-name $function --profile $profile --region $region
aws lambda list-tags --resource (aws lambda get-function --function-name $function --query 'Configuration.FunctionArn' --output text --profile $profile --region $region) --profile $profile --region $region
aws lambda get-function-concurrency --function-name $function --profile $profile --region $region
```

Set `$previous` to the exact `previous_reserved_concurrency` recorded by the failed run, then restore it:

```powershell
$previous = 5 # Replace with the recorded value; do not assume 5.
aws lambda put-function-concurrency --function-name $function --reserved-concurrent-executions $previous --profile $profile --region $region
```

If the fixture had no reserved-concurrency setting before the run, remove the setting instead of assigning a guessed value:

```powershell
aws lambda delete-function-concurrency --function-name $function --profile $profile --region $region
```

Verify with `get-function-concurrency`. These commands change a real AWS resource. Run them only against the dedicated AndonCore sandbox fixture, never a production workload. If the previous value is unknown, stop and ask the sandbox owner to inspect CloudTrail/stack history before making a change.

## Notifications

Bootstrap can optionally subscribe `SECURITY_ALERT_EMAIL` to the stack's SNS security-alert topic. The recipient must confirm SNS's email before delivery begins. The stack only creates the subscription; it does not turn the simulated escalation queue into a live incident-management integration.
