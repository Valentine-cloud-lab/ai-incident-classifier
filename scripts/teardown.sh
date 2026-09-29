#!/usr/bin/env bash
# teardown.sh  Removes the lab stacks to stop charges (interface endpoints bill hourly).
# Versioned buckets must be emptied first or stack deletion fails.
set -euo pipefail
PROJECT="${PROJECT:-aic}"
export AWS_DEFAULT_REGION="${AWS_REGION:-us-east-1}"
ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
empty() {
  python3 - "$1" << 'PY'
import subprocess, json, sys
b = sys.argv[1]
while True:
    r = json.loads(subprocess.check_output(["aws", "s3api", "list-object-versions", "--bucket", b, "--output", "json"]) or b"{}")
    objs = [{"Key": o["Key"], "VersionId": o["VersionId"]} for o in r.get("Versions", []) + r.get("DeleteMarkers", [])]
    if not objs:
        break
    subprocess.check_call(["aws", "s3api", "delete-objects", "--bucket", b,
                           "--delete", json.dumps({"Objects": objs[:1000]})], stdout=subprocess.DEVNULL)
PY
}
empty "${PROJECT}-artifacts-${ACCOUNT}-${AWS_DEFAULT_REGION}" || true
aws cloudformation delete-stack --stack-name "${PROJECT}-incident-classifier"
aws cloudformation wait stack-delete-complete --stack-name "${PROJECT}-incident-classifier"
echo "Main stack deleted. The config-recorder stack stays so AWS Config keeps recording."
