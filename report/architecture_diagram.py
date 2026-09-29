"""
architecture_diagram.py
Draws Figure 1 (results/architecture.png) at its printed size, 6.5 x 3.55 inches,
so every label prints at 7.5 to 8.5 pt. Numbers 1-8 follow one alert through the
pipeline and match the numbered references in the report text.
Run:  python report/architecture_diagram.py
"""
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch  # noqa: E402

OUT = Path(__file__).resolve().parent.parent / "results" / "architecture.png"
W, H = 6.5, 3.55
fig = plt.figure(figsize=(W, H), dpi=300)
ax = fig.add_axes([0, 0, 1, 1])
ax.set_xlim(0, W)
ax.set_ylim(0, H)
ax.axis("off")

INK = "#1F2937"


def box(x, y, w, h, title, body, fill, edge="#4B5563", lw=0.9, rounded=True):
    style = "round,pad=0,rounding_size=0.08" if rounded else "square,pad=0"
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle=style, fc=fill, ec=edge, lw=lw))
    ax.text(x + w / 2, y + h - 0.07, title, ha="center", va="top", fontsize=8.3, fontweight="bold", color=INK)
    ax.text(x + w / 2, y + h - 0.24, body, ha="center", va="top", fontsize=7.4, color=INK, linespacing=1.25)
    return (x, y, w, h)


def arrow(p, q, style="-|>", color="#374151", ls="-", conn="arc3"):
    ax.add_patch(FancyArrowPatch(p, q, arrowstyle=style, mutation_scale=8, color=color, lw=0.9,
                                 linestyle=ls, connectionstyle=conn, shrinkA=0, shrinkB=0))


# Row 1: intake
box(0.05, 2.85, 1.55, 0.65, "Alert sources", "Security Hub, GuardDuty,\nConfig rules, CloudWatch,\nmanual reports", "#F3F4F6")
box(1.85, 2.85, 1.35, 0.65, "1  EventBridge rule", "one $or pattern\n5 event types", "#FEF3C7")
box(3.45, 2.85, 1.40, 0.65, "2  SQS queue", "accepts this rule only\nbatches of 10", "#FEF3C7")
box(5.10, 2.85, 1.35, 0.65, "Dead-letter queue", "after 3 failures\nalarm to SecOps", "#FEE2E2", edge="#B91C1C")
arrow((1.60, 3.17), (1.85, 3.17))
arrow((3.20, 3.17), (3.45, 3.17))
arrow((4.85, 3.17), (5.10, 3.17), color="#B91C1C", ls="--")

# Row 2: private VPC
ax.add_patch(FancyBboxPatch((0.55, 1.02), 4.45, 1.43, boxstyle="round,pad=0,rounding_size=0.10",
                            fc="none", ec="#1D4ED8", lw=1.3))
ax.text(0.68, 2.38, "Private VPC 10.40.0.0/16", fontsize=7.8, fontweight="bold", color="#1D4ED8", va="top")
ax.text(0.68, 2.22, "no internet gateway, no NAT, flow logs on", fontsize=7.0, color="#1D4ED8", va="top")
box(0.70, 1.12, 2.30, 0.80, "3  Lambda classifier",
    "Tier 1: TF-IDF + logistic regression\nconfidence below 0.60: ask Tier 2\nTier 2 failure: MANUAL_TRIAGE",
    "#DBEAFE", edge="#1D4ED8", lw=1.3)
box(3.30, 1.12, 1.55, 0.80, "4  VPC endpoints", "HTTPS 443 only\nSG chaining\nendpoint policies", "#DBEAFE")
arrow((3.00, 1.52), (3.30, 1.52))
# SQS down to Lambda (elbow)
ax.plot([4.15, 4.15, 2.85, 2.85], [2.85, 2.62, 2.62, 2.05], color="#374151", lw=0.9)
arrow((2.85, 2.06), (2.85, 1.92))
ax.text(4.20, 2.70, "poll", fontsize=7.0, color=INK, va="center")

# KMS legend box
box(5.15, 1.45, 1.30, 1.00, "KMS key", "rotation on\nencrypts SQS, DLQ,\nS3, DynamoDB, SNS,\nLambda env, logs",
    "#FFF1F2", edge="#BE123C", rounded=False)

# Row 3: services reached through the endpoints
row = [(0.05, "5  S3", "model artifact\nSHA-256 checked", "#DCFCE7"),
       (1.65, "6  Bedrock", "Claude Haiku 4.5\nlow confidence only", "#EDE9FE"),
       (3.25, "7  DynamoDB", "decision log\n90-day TTL", "#DCFCE7"),
       (4.85, "8  SNS topics", "SecOps, NetOps,\nCloudOps + runbook", "#DCFCE7")]
for x, t, b, c in row:
    box(x, 0.05, 1.55, 0.62, t, b, c)
    arrow((4.075, 1.12), (x + 0.775, 0.67))

fig.savefig(OUT, dpi=300)
print(f"wrote {OUT}")
