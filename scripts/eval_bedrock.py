"""
eval_bedrock.py
Measures the full two-tier system on the hard set with live Bedrock calls.
Offline evaluation (training/evaluate.py) cannot score the Bedrock tier, so
this script closes the gap. Run from AWS CloudShell or any shell with boto3
and bedrock:InvokeModel permission on the model below.

Only alerts the local model escalates (confidence < threshold) go to Bedrock,
which mirrors production behavior and keeps the run to roughly 86 calls.

Usage:  python3 scripts/eval_bedrock.py [--model-id ID] [--threshold 0.60]
Output: results/bedrock_eval.json
"""
import argparse
import json
import sys
import time
from pathlib import Path

import boto3

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
import llm_fallback  # noqa: E402
from classifier import IncidentClassifier  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model-id", default="us.anthropic.claude-haiku-4-5-20251001-v1:0")
    ap.add_argument("--threshold", type=float, default=0.60)
    args = ap.parse_args()

    model = IncidentClassifier.from_json((ROOT / "model" / "model.json").read_text())
    bedrock = boto3.client("bedrock-runtime")
    rows = [json.loads(line) for line in open(ROOT / "data" / "alerts_hard.jsonl", encoding="utf-8")]

    correct = local_auto = llm_calls = llm_correct = manual = 0
    latencies, details = [], []
    for row in rows:
        label, conf = model.predict(row["text"])
        tier, final = "local_model", label
        if conf < args.threshold:
            llm_calls += 1
            start = time.perf_counter()
            result = llm_fallback.classify(bedrock, args.model_id, row["text"])
            latencies.append((time.perf_counter() - start) * 1000)
            if result:
                tier, final = "bedrock", result["category"]
                llm_correct += final == row["label"]
            else:
                tier, final = "manual", "MANUAL_TRIAGE"
                manual += 1
        else:
            local_auto += 1
        correct += final == row["label"]
        details.append({"text": row["text"], "true": row["label"], "pred": final, "tier": tier})

    latencies.sort()
    summary = {
        "model_id": args.model_id,
        "threshold": args.threshold,
        "n": len(rows),
        "end_to_end_accuracy": round(correct / len(rows), 4),
        "local_auto_routed": local_auto,
        "bedrock_calls": llm_calls,
        "bedrock_accuracy": round(llm_correct / llm_calls, 4) if llm_calls else None,
        "manual_triage": manual,
        "bedrock_latency_ms_p50": round(latencies[len(latencies) // 2], 1) if latencies else None,
        "bedrock_latency_ms_max": round(latencies[-1], 1) if latencies else None,
    }
    (ROOT / "results" / "bedrock_eval.json").write_text(json.dumps({"summary": summary, "details": details}, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
