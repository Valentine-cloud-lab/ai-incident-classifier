# Evidence checklist

Run `./scripts/verify_controls.sh`. Each check writes `evidence/E#.txt`.
Save a screenshot of the terminal output or the console page below as
`evidence/E#.png`, then rerun `python report/build_report.py`. The script
places every E#.png into Appendix A with its caption.

| ID | Control | Console location |
|----|---------|------------------|
| E1 | IAM least privilege | IAM > Roles > aic-classifier-role > Permissions |
| E2 | KMS CMK and rotation | KMS > Customer managed keys > alias/aic-data > Key rotation |
| E3 | S3 SSE-KMS, Block Public Access, TLS-only policy | S3 > aic-artifacts-... > Properties and Permissions |
| E4 | Security group chaining | VPC > Security groups > aic-lambda-sg and aic-endpoint-sg |
| E5 | Endpoints, no IGW/NAT, flow logs | VPC > Endpoints, and VPC > Your VPCs > aic-vpc > Flow logs |
| E6 | Lambda in VPC, encrypted env vars | Lambda > aic-classifier > Configuration > VPC |
| E7 | DynamoDB and SNS KMS encryption | DynamoDB > aic-incidents > Additional settings, SNS > Topics > Encryption |
| E8 | AWS Config recorder and rule compliance | AWS Config > Rules (filter "aic-") |
| E9 | Pipeline output | CloudShell output of send_test_events.sh |
