#!/usr/bin/env bash
# deploy.sh
# Tests, packages, and deploys the incident classifier. Built for AWS CloudShell
# (aws CLI v2 and python3 preinstalled). Idempotent: safe to run again.
#
# Usage:  AWS_REGION=us-east-1 ALERT_EMAIL=you@example.com ./scripts/deploy.sh
# Optional: RESERVED=5 (reserved concurrency), CSPM=true (enable Security Hub CSPM + CIS v3.0.0)
set -euo pipefail

REGION="${AWS_REGION:-us-east-1}"
PROJECT="${PROJECT:-aic}"
STACK="${PROJECT}-incident-classifier"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
export AWS_DEFAULT_REGION="$REGION"

echo "[1/7] Unit tests"
(cd "$ROOT" && python3 -m unittest discover -s tests)

echo "[2/7] AWS Config recorder (one per Region)"
COUNT="$(aws configservice describe-configuration-recorders --query 'length(ConfigurationRecorders)' --output text)"
if [ "$COUNT" = "0" ]; then
  aws cloudformation deploy --stack-name "${PROJECT}-config-recorder" \
    --template-file "$ROOT/infra/config-recorder.yaml" \
    --parameter-overrides ProjectName="$PROJECT" --capabilities CAPABILITY_NAMED_IAM
fi
RECORDER="$(aws configservice describe-configuration-recorders --query 'ConfigurationRecorders[0].name' --output text)"
aws configservice start-configuration-recorder --configuration-recorder-name "$RECORDER"

echo "[3/7] Look up gateway endpoint prefix lists for SG egress rules"
S3_PL="$(aws ec2 describe-managed-prefix-lists --filters Name=prefix-list-name,Values=com.amazonaws.$REGION.s3 \
  --query 'PrefixLists[0].PrefixListId' --output text)"
DDB_PL="$(aws ec2 describe-managed-prefix-lists --filters Name=prefix-list-name,Values=com.amazonaws.$REGION.dynamodb \
  --query 'PrefixLists[0].PrefixListId' --output text)"
echo "    S3=$S3_PL DynamoDB=$DDB_PL"

echo "[4/7] Private, encrypted staging bucket for the Lambda package"
STAGING="${PROJECT}-cfn-staging-${ACCOUNT}-${REGION}"
if ! aws s3api head-bucket --bucket "$STAGING" 2>/dev/null; then
  if [ "$REGION" = "us-east-1" ]; then
    aws s3api create-bucket --bucket "$STAGING"
  else
    aws s3api create-bucket --bucket "$STAGING" --create-bucket-configuration LocationConstraint="$REGION"
  fi
  aws s3api put-public-access-block --bucket "$STAGING" --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
  aws s3api put-bucket-encryption --bucket "$STAGING" --server-side-encryption-configuration \
    '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"},"BucketKeyEnabled":true}]}'
fi
# TLS-only policy (CIS 2.1.1). Added after the first live run, when the Config rule
# s3-bucket-ssl-requests-only flagged this CLI-built bucket. Safe to reapply.
aws s3api put-bucket-policy --bucket "$STAGING" --policy "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"DenyInsecureTransport\",\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":[\"arn:aws:s3:::$STAGING\",\"arn:aws:s3:::$STAGING/*\"],\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}}]}"

echo "[5/7] Package and deploy the main stack"
aws cloudformation package --template-file "$ROOT/infra/template.yaml" --s3-bucket "$STAGING" \
  --s3-prefix lambda --output-template-file "$ROOT/infra/packaged.yaml"
PARAMS=(ProjectName="$PROJECT" ModelSha256="$(tr -d '[:space:]' < "$ROOT/model/model.sha256")"
        S3PrefixListId="$S3_PL" DynamoDbPrefixListId="$DDB_PL"
        ReservedConcurrency="${RESERVED:-0}" EnableSecurityHubCspm="${CSPM:-false}")
[ -n "${ALERT_EMAIL:-}" ] && PARAMS+=(AlertEmail="$ALERT_EMAIL")
aws cloudformation deploy --stack-name "$STACK" --template-file "$ROOT/infra/packaged.yaml" \
  --parameter-overrides "${PARAMS[@]}" --capabilities CAPABILITY_NAMED_IAM

out() { aws cloudformation describe-stacks --stack-name "$STACK" \
  --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" --output text; }

echo "[6/7] Upload the model artifact (bucket default encryption applies SSE-KMS)"
aws s3 cp "$ROOT/model/model.json" "s3://$(out ArtifactBucketName)/model/model.json"

echo "[7/7] Strip all rules from the VPC default security group (CIS 5.4)"
VPC="$(out VpcId)"
DSG="$(aws ec2 describe-security-groups --filters Name=vpc-id,Values="$VPC" Name=group-name,Values=default \
  --query 'SecurityGroups[0].GroupId' --output text)"
IN="$(aws ec2 describe-security-groups --group-ids "$DSG" --query 'SecurityGroups[0].IpPermissions' --output json)"
EG="$(aws ec2 describe-security-groups --group-ids "$DSG" --query 'SecurityGroups[0].IpPermissionsEgress' --output json)"
[ "$IN" != "[]" ] && aws ec2 revoke-security-group-ingress --group-id "$DSG" --ip-permissions "$IN" >/dev/null
[ "$EG" != "[]" ] && aws ec2 revoke-security-group-egress --group-id "$DSG" --ip-permissions "$EG" >/dev/null

echo "Deployed $STACK in $REGION. Next: ./scripts/send_test_events.sh then ./scripts/verify_controls.sh"
