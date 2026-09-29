#!/usr/bin/env bash
# verify_controls.sh
# Prints read-only evidence for every security control and saves each check
# to evidence/<id>.txt. Screenshot the terminal or the matching console page
# for each ID listed in SCREENSHOTS.md.
set -uo pipefail
PROJECT="${PROJECT:-aic}"
STACK="${PROJECT}-incident-classifier"
export AWS_DEFAULT_REGION="${AWS_REGION:-us-east-1}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$ROOT/evidence"
out() { aws cloudformation describe-stacks --stack-name "$STACK" \
  --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" --output text; }

BUCKET="$(out ArtifactBucketName)"; KEY="$(out KmsKeyArn)"; FN="$(out FunctionName)"
TABLE="$(out TableName)"; LSG="$(out LambdaSecurityGroupId)"; ESG="$(out EndpointSecurityGroupId)"
VPC="$(out VpcId)"

run() {  # run <evidence-id> <title> <command...>
  local id="$1" title="$2"; shift 2
  { echo "=== $id  $title ==="; "$@"; echo; } 2>&1 | tee "$ROOT/evidence/$id.txt"
}

run E1 "IAM role inline policy (least privilege)" \
  aws iam get-role-policy --role-name "${PROJECT}-classifier-role" --policy-name classifier-least-privilege
run E2 "KMS key state and rotation" bash -c \
  "aws kms describe-key --key-id $KEY --query 'KeyMetadata.[KeyId,KeyState,KeyManager]' --output text; \
   aws kms get-key-rotation-status --key-id $KEY"
run E3 "S3 encryption, public access block, TLS-only policy" bash -c \
  "aws s3api get-bucket-encryption --bucket $BUCKET; \
   aws s3api get-public-access-block --bucket $BUCKET; \
   aws s3api get-bucket-policy --bucket $BUCKET --query Policy --output text | python3 -m json.tool"
run E4 "Security group chaining" \
  aws ec2 describe-security-groups --group-ids "$LSG" "$ESG" \
  --query 'SecurityGroups[].{Name:GroupName,Ingress:IpPermissions,Egress:IpPermissionsEgress}'
run E5 "VPC endpoints, no IGW/NAT, flow logs" bash -c \
  "aws ec2 describe-vpc-endpoints --filters Name=vpc-id,Values=$VPC \
     --query 'VpcEndpoints[].[ServiceName,VpcEndpointType,State]' --output table; \
   aws ec2 describe-internet-gateways --filters Name=attachment.vpc-id,Values=$VPC --query 'length(InternetGateways)'; \
   aws ec2 describe-nat-gateways --filter Name=vpc-id,Values=$VPC --query 'length(NatGateways)'; \
   aws ec2 describe-flow-logs --filter Name=resource-id,Values=$VPC --query 'FlowLogs[].[FlowLogStatus,LogDestination]' --output text"
run E6 "Lambda VPC placement and env encryption" \
  aws lambda get-function-configuration --function-name "$FN" \
  --query '{Vpc:VpcConfig,KmsKey:KMSKeyArn,Runtime:Runtime}'
run E7 "DynamoDB and SNS encryption" bash -c \
  "aws dynamodb describe-table --table-name $TABLE --query 'Table.SSEDescription'; \
   for t in secops netops cloudops; do \
     aws sns get-topic-attributes --topic-arn arn:aws:sns:$AWS_DEFAULT_REGION:$(aws sts get-caller-identity --query Account --output text):${PROJECT}-\$t \
       --query 'Attributes.KmsMasterKeyId' --output text; done"
run E8 "AWS Config recorder and rule compliance" bash -c \
  "aws configservice describe-configuration-recorder-status --query 'ConfigurationRecordersStatus[].[name,recording,lastStatus]' --output text; \
   aws configservice describe-compliance-by-config-rule \
     --config-rule-names $(aws configservice describe-config-rules --query "ConfigRules[?starts_with(ConfigRuleName, '${PROJECT}-')].ConfigRuleName" --output text) \
     --query 'ComplianceByConfigRules[].[ConfigRuleName,Compliance.ComplianceType]' --output table"
