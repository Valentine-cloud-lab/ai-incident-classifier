"""
handler.py
AWS Lambda entry point for AI-assisted incident classification.

Flow for each SQS record (one EventBridge event per record):
  1. Extract readable text from a Security Hub, GuardDuty, AWS Config,
     CloudWatch alarm, or custom incident event.
  2. Score the text with the local TF-IDF + logistic regression model.
  3. If the top probability is below CONFIDENCE_THRESHOLD, ask Bedrock.
     If Bedrock fails or returns an invalid answer, route to MANUAL_TRIAGE.
  4. Write the decision to DynamoDB (conditional put, so SQS redelivery does
     not create duplicates) and publish to the owning team's SNS topic.
Failed records return in batchItemFailures so SQS retries only those records
and moves repeat failures to the dead-letter queue after 3 attempts.

Environment variables (set by infra/template.yaml):
  MODEL_BUCKET, MODEL_KEY, MODEL_SHA256, TABLE_NAME, BEDROCK_MODEL_ID,
  CONFIDENCE_THRESHOLD, TOPIC_SECOPS, TOPIC_NETOPS, TOPIC_CLOUDOPS
Optional for local runs: MODEL_PATH (read model.json from disk instead of S3)
"""
import hashlib
import json
import logging
import os
import time
from datetime import datetime, timezone

import llm_fallback
import routing
from classifier import IncidentClassifier

log = logging.getLogger()
log.setLevel(logging.INFO)

_clients = {}
_model = None


def client(name):
    """Create boto3 clients once per execution environment (cold start)."""
    if name not in _clients:
        import boto3  # imported here so unit tests run without boto3 installed
        _clients[name] = boto3.client(name)
    return _clients[name]


def load_model() -> IncidentClassifier:
    """Load model.json once, verify its SHA-256, and cache the result.

    The hash check stops a tampered or partially uploaded model from ever
    scoring alerts. Mismatch raises, the batch fails, and SQS retries.
    """
    global _model
    if _model is None:
        if os.environ.get("MODEL_PATH"):
            with open(os.environ["MODEL_PATH"], "rb") as fh:
                raw = fh.read()
        else:
            obj = client("s3").get_object(Bucket=os.environ["MODEL_BUCKET"],
                                          Key=os.environ["MODEL_KEY"])
            raw = obj["Body"].read()
        expected = os.environ.get("MODEL_SHA256", "").strip()
        actual = hashlib.sha256(raw).hexdigest()
        if expected and actual != expected:
            raise RuntimeError(f"model hash mismatch: expected {expected}, got {actual}")
        _model = IncidentClassifier.from_json(raw.decode("utf-8"))
    return _model


def extract_text(event: dict) -> tuple:
    """Return (event_id, text, source) for the supported event shapes."""
    detail = event.get("detail", {}) or {}
    source = event.get("source", "unknown")
    event_id = event.get("id", "")

    if source == "aws.securityhub":
        f = (detail.get("findings") or [{}])[0]
        event_id = f.get("Id", event_id)
        text = f"{f.get('Title', '')}. {f.get('Description', '')}"
    elif source == "aws.guardduty":
        event_id = detail.get("id", event_id)
        text = f"{detail.get('type', '')}. {detail.get('title', '')}. {detail.get('description', '')}"
    elif source == "aws.config":
        text = (f"AWS Config rule {detail.get('configRuleName', '')} NON_COMPLIANT for "
                f"{detail.get('resourceType', '')} {detail.get('resourceId', '')}")
    elif source == "aws.cloudwatch":
        cfg = detail.get("configuration", {}) or {}
        state = detail.get("state", {}) or {}
        text = f"{detail.get('alarmName', '')}. {cfg.get('description', '')}. {state.get('reason', '')}"
    else:  # custom.incident and anything else: accept a free-text description
        text = str(detail.get("description") or detail.get("title") or json.dumps(detail))[:2000]
    return event_id, " ".join(text.split()), source


def classify(text: str) -> dict:
    """Two-tier decision: local model first, Bedrock only on low confidence."""
    threshold = float(os.environ.get("CONFIDENCE_THRESHOLD", "0.60"))
    label, conf = load_model().predict(text)
    decision = {"category": label, "confidence": round(conf, 4), "tier": "local_model",
                "model_version": load_model().version}
    if conf < threshold:
        llm = llm_fallback.classify(client("bedrock-runtime"),
                                    os.environ["BEDROCK_MODEL_ID"], text)
        if llm:
            decision.update(category=llm["category"], confidence=round(llm["confidence"], 4),
                            tier="bedrock", rationale=llm["rationale"],
                            local_guess=label, local_confidence=round(conf, 4))
        else:
            decision.update(category="MANUAL_TRIAGE", tier="fallback_manual",
                            local_guess=label, local_confidence=round(conf, 4))
    return decision


def process(record: dict) -> dict:
    started = time.perf_counter()
    event = json.loads(record["body"])
    event_id, text, source = extract_text(event)
    if not text:
        raise ValueError("event contained no classifiable text")

    decision = classify(text)
    target = routing.route(decision["category"])
    now = datetime.now(timezone.utc)
    item = {
        "pk": {"S": event_id or record["messageId"]},
        "received_at": {"S": now.isoformat()},
        "source": {"S": source},
        "category": {"S": target["category"]},
        "tier": {"S": decision["tier"]},
        "confidence": {"N": str(decision["confidence"])},
        "alert_text": {"S": text[:2000]},
        "latency_ms": {"N": str(round((time.perf_counter() - started) * 1000, 2))},
        "expires_at": {"N": str(int(now.timestamp()) + 90 * 86400)},  # 90-day TTL
    }
    try:
        client("dynamodb").put_item(TableName=os.environ["TABLE_NAME"], Item=item,
                                    ConditionExpression="attribute_not_exists(pk)")
    except Exception as err:
        # Conditional check failure means a redelivered duplicate. Skip publish.
        if "ConditionalCheckFailed" in type(err).__name__ or "ConditionalCheckFailed" in str(err):
            log.info(json.dumps({"duplicate": event_id}))
            return decision
        raise

    message = {"event_id": event_id, "source": source, "alert": text[:1000], **decision,
               "category": target["category"], "remediation": target["remediation"]}
    client("sns").publish(
        TopicArn=target["topic_arn"],
        Subject=f"[{target['category']}] incident routed"[:100],
        Message=json.dumps(message, indent=2),
        MessageAttributes={"category": {"DataType": "String", "StringValue": target["category"]}},
    )
    log.info(json.dumps({"event_id": event_id, "category": target["category"],
                         "tier": decision["tier"], "confidence": decision["confidence"]}))
    return decision


def lambda_handler(event, context):
    """SQS batch entry point with partial batch failure reporting."""
    failures = []
    for record in event.get("Records", []):
        try:
            process(record)
        except Exception as err:
            log.exception("record %s failed: %s", record.get("messageId"), err)
            failures.append({"itemIdentifier": record["messageId"]})
    return {"batchItemFailures": failures}
