# AI-Assisted Incident Classification (CLCS 605, Unit 6)

Scenario 2, Automated Incident Classification. An EventBridge -> SQS -> Lambda
workflow reads Security Hub, GuardDuty, AWS Config, CloudWatch, and manual
incident alerts, classifies each one into five categories with a local NLP
model, escalates low-confidence alerts to Claude Haiku 4.5 on Amazon Bedrock,
and routes the result with a reviewed runbook to the owning team's SNS topic.

## Repository layout

| Path | Purpose |
|------|---------|
| `src/handler.py` | Lambda entry point: text extraction, two-tier decision, DynamoDB write, SNS publish |
| `src/classifier.py` | Pure-Python TF-IDF + logistic regression inference (no dependencies) |
| `src/llm_fallback.py` | Bedrock Converse call with forced, enum-bound tool output |
| `src/routing.py` | Category -> team topic and static remediation runbooks |
| `training/generate_dataset.py` | Synthetic labeled alert corpus (seed 605) |
| `training/train.py` | scikit-learn training, log-loss model selection, export, parity check |
| `training/evaluate.py` | Keyword baseline vs AI classifier, metrics, confusion matrix |
| `infra/template.yaml` | Main CloudFormation stack (45 resources) |
| `infra/config-recorder.yaml` | AWS Config recorder + encrypted delivery bucket |
| `scripts/deploy.sh` | Test, package, deploy, upload model, close default SG |
| `scripts/send_test_events.sh` | Six sample alerts, including a prompt-injection attempt |
| `scripts/verify_controls.sh` | Writes evidence files E1-E8 for the report appendix |
| `scripts/eval_bedrock.py` | Live measurement of the Bedrock tier on the hard set |
| `scripts/teardown.sh` | Deletes the main stack |
| `tests/test_pipeline.py` | 15 offline unit tests with in-memory AWS fakes |
| `results/` | metrics.json, evaluation.txt, confusion matrix, test output, diagram |
| `report/build_report.py` | Rebuilds the PDF report, embedding evidence/E*.png if present |

## Reproduce the offline results

```bash
pip install scikit-learn matplotlib   # training and evaluation only
python training/generate_dataset.py
python training/train.py
python training/evaluate.py
python -m unittest discover -s tests -v
```

## Deploy (AWS CloudShell, us-east-1)

1. Submit the one-time Anthropic use-case form in Amazon Bedrock. New accounts sometimes start with a zero daily token quota for Bedrock models; if the Playground returns "Too many tokens per day," open an Account and billing support case. The pipeline still runs and routes low-confidence alerts to MANUAL_TRIAGE.
2. `git clone <this repo> && cd ai-incident-classifier && chmod +x scripts/*.sh`
3. `ALERT_EMAIL=you@example.com ./scripts/deploy.sh`
   Optional: `RESERVED=5` (reserved concurrency) and `CSPM=true` (enable Security Hub CSPM with CIS v3.0.0).
4. Confirm the SNS subscription email.
5. `./scripts/send_test_events.sh`
6. `./scripts/verify_controls.sh`
7. `python3 scripts/eval_bedrock.py` (needs boto3 and bedrock:InvokeModel)
8. `./scripts/teardown.sh` when finished. The two interface endpoints cost about $0.96 per day.

## Rebuild the report

```bash
pip install reportlab
REPO_URL=https://github.com/<you>/ai-incident-classifier python report/build_report.py
```
