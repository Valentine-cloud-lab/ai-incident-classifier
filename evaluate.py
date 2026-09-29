"""
evaluate.py
Compares two routers on the held-out test set and the hard (unseen wording) set:

  1. Keyword baseline: ordered substring rules, first match wins. This mirrors
     the static EventBridge-pattern or ticket-rule routing most teams run today.
     No match means the alert lands in a manual triage queue.
  2. AI classifier: the exported model.json run through the same pure-Python
     code the Lambda function uses. Predictions below the confidence threshold
     escalate to the Bedrock second opinion (not called offline) and count here
     as "escalated", never as correct.

Metrics
  accuracy            share of all alerts routed to the correct team
  macro-F1            per-class F1 averaged, so each class counts equally
  auto-route rate     share of alerts routed with no human or LLM step
  auto-route precision  accuracy on the alerts routed automatically
  misroute rate       share of alerts sent to the WRONG team (the costly error)
  p50 / p99 latency   per-alert classification time in this container

Outputs: results/metrics.json, results/evaluation.txt, results/confusion_matrix.png
Run:     python training/evaluate.py
"""
import json
import statistics
import sys
import time
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from sklearn.metrics import confusion_matrix, f1_score  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from classifier import IncidentClassifier  # noqa: E402

CLASSES = ["IDENTITY_ACCESS", "NETWORK_EXPOSURE", "DATA_PROTECTION",
           "COMPUTE_AVAILABILITY", "THREAT_DETECTION"]
THRESHOLD = 0.60  # policy value, fixed before looking at test results

# Ordered rules. Earlier rules win, which is how most rule engines behave.
KEYWORD_RULES = [
    ("THREAT_DETECTION", ["malware", "mining", "malicious", "trojan", "command and control",
                          "exfiltration", "tor ", "backdoor", "brute force", "port scan", "reverse shell"]),
    ("IDENTITY_ACCESS", ["iam", "mfa", "root account", "access key", "password", "assumerole",
                         "credentials", "console login"]),
    ("NETWORK_EXPOSURE", ["security group", "network acl", "0.0.0.0/0", "::/0", "flow log",
                          "route table", "rdp", "ssh", "peering", "listener", "public ip"]),
    ("DATA_PROTECTION", ["s3", "encrypt", "kms", "macie", "snapshot", "point-in-time", "bucket"]),
    ("COMPUTE_AVAILABILITY", ["cpu", "memory", "status check", "unhealthy", "error rate",
                              "throttl", "auto scaling", "disk", "storage space", "task count"]),
]


def keyword_route(text):
    low = text.lower()
    for label, words in KEYWORD_RULES:
        if any(w in low for w in words):
            return label
    return "UNROUTED"


def load(name):
    with open(ROOT / "data" / name, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh]


def score(y_true, y_pred):
    n = len(y_true)
    auto = [(t, p) for t, p in zip(y_true, y_pred) if p in CLASSES]
    correct = sum(t == p for t, p in zip(y_true, y_pred))
    auto_ok = sum(t == p for t, p in auto)
    return {
        "n": n,
        "accuracy": round(correct / n, 4),
        "macro_f1": round(f1_score(y_true, y_pred, labels=CLASSES, average="macro", zero_division=0), 4),
        "auto_route_rate": round(len(auto) / n, 4),
        "auto_route_precision": round(auto_ok / len(auto), 4) if auto else None,
        "misroute_rate": round((len(auto) - auto_ok) / n, 4),
    }


def main():
    model = IncidentClassifier.from_json((ROOT / "model" / "model.json").read_text())
    report, lines = {"threshold": THRESHOLD, "model_version": model.version}, []

    for name in ["alerts_test.jsonl", "alerts_hard.jsonl"]:
        rows = load(name)
        y = [r["label"] for r in rows]
        kw = [keyword_route(r["text"]) for r in rows]

        ai_raw, ai_gated, confs, timings = [], [], [], []
        for r in rows:
            start = time.perf_counter()
            label, conf = model.predict(r["text"])
            timings.append((time.perf_counter() - start) * 1000)
            ai_raw.append(label)
            confs.append(conf)
            ai_gated.append(label if conf >= THRESHOLD else "ESCALATED")

        # Escalated alerts where the model's top guess was still right show
        # how much work the LLM tier actually needs to do.
        esc_idx = [i for i, p in enumerate(ai_gated) if p == "ESCALATED"]
        sweep = {}
        for t in [0.40, 0.50, 0.60, 0.70, 0.80, 0.90]:
            gated = [p if c >= t else "ESCALATED" for p, c in zip(ai_raw, confs)]
            sweep[str(t)] = score(y, gated)

        timings.sort()
        report[name] = {
            "keyword_baseline": score(y, kw),
            "ai_no_threshold": score(y, ai_raw),
            "ai_with_threshold": score(y, ai_gated),
            "escalated_count": len(esc_idx),
            "escalated_top_guess_correct": sum(ai_raw[i] == y[i] for i in esc_idx),
            "threshold_sweep": sweep,
            "latency_ms_p50": round(statistics.median(timings), 4),
            "latency_ms_p99": round(timings[int(len(timings) * 0.99) - 1], 4),
        }
        lines.append(f"== {name} (n={len(rows)}) ==")
        for key in ["keyword_baseline", "ai_no_threshold", "ai_with_threshold"]:
            lines.append(f"{key:<20} {report[name][key]}")
        lines.append(f"escalated={len(esc_idx)} top_guess_correct={report[name]['escalated_top_guess_correct']}")
        lines.append(f"latency p50={report[name]['latency_ms_p50']} ms p99={report[name]['latency_ms_p99']} ms")
        lines.append("misrouted examples (ai_with_threshold):")
        for r, p in zip(rows, ai_gated):
            if p in CLASSES and p != r["label"]:
                lines.append(f"  true={r['label']} pred={p} :: {r['text'][:110]}")
        lines.append("")

        if name == "alerts_hard.jsonl":
            cm = confusion_matrix(y, ai_raw, labels=CLASSES)
            fig, ax = plt.subplots(figsize=(6.2, 5.2))
            ax.imshow(cm, cmap="Blues")
            short = ["IDENT", "NETWK", "DATA", "COMPUTE", "THREAT"]
            ax.set_xticks(range(5), short)
            ax.set_yticks(range(5), short)
            for i in range(5):
                for j in range(5):
                    ax.text(j, i, cm[i, j], ha="center", va="center",
                            color="white" if cm[i, j] > cm.max() / 2 else "black")
            ax.set_xlabel("Predicted")
            ax.set_ylabel("True")
            ax.set_title("AI classifier, hard set (no threshold), n=150")
            fig.tight_layout()
            fig.savefig(ROOT / "results" / "confusion_matrix.png", dpi=200)

    (ROOT / "results").mkdir(exist_ok=True)
    (ROOT / "results" / "metrics.json").write_text(json.dumps(report, indent=2))
    (ROOT / "results" / "evaluation.txt").write_text("\n".join(lines))
    print("\n".join(lines))


if __name__ == "__main__":
    main()
