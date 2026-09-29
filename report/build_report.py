"""
build_report.py
Builds the Unit 6 report PDF (12 pt Times, double-spaced body, 1-inch margins).
Reads live numbers from results/metrics.json so the report always matches the
latest evaluation run. Screenshots saved as evidence/E1.png ... evidence/E9.png
are appended to Appendix A automatically.

Run:  REPO_URL=https://github.com/<you>/ai-incident-classifier python report/build_report.py
"""
import json
import os
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (CondPageBreak, Image, KeepTogether, PageBreak, Paragraph, Preformatted,
                                SimpleDocTemplate, Spacer, Table, TableStyle)

ROOT = Path(__file__).resolve().parent.parent
OUT = Path(os.environ.get("REPORT_OUT", ROOT / "report" / "Unit6_AI_Incident_Classification_Report.pdf"))
REPO = os.environ.get("REPO_URL", "https://github.com/[your-username]/ai-incident-classifier")
M = json.loads((ROOT / "results" / "metrics.json").read_text())
T, H = M["alerts_test.jsonl"], M["alerts_hard.jsonl"]
MODEL = json.loads((ROOT / "model" / "model.json").read_text())


def pct(x):
    return f"{x * 100:.1f}%"


# ---------------------------------------------------------------- styles
body = ParagraphStyle("body", fontName="Times-Roman", fontSize=12, leading=24,
                      firstLineIndent=0.5 * inch, alignment=TA_LEFT)
noindent = ParagraphStyle("noindent", parent=body, firstLineIndent=0)
h1 = ParagraphStyle("h1", fontName="Times-Bold", fontSize=12, leading=24, alignment=TA_CENTER)
caption = ParagraphStyle("cap", fontName="Times-Italic", fontSize=11, leading=14, spaceBefore=2, spaceAfter=6)
label = ParagraphStyle("lab", fontName="Times-Bold", fontSize=11, leading=14, spaceBefore=4)
title = ParagraphStyle("title", fontName="Times-Bold", fontSize=14, leading=24, alignment=TA_CENTER)
center = ParagraphStyle("center", fontName="Times-Roman", fontSize=12, leading=24, alignment=TA_CENTER)
cell = ParagraphStyle("cell", fontName="Times-Roman", fontSize=9, leading=11)
cellb = ParagraphStyle("cellb", parent=cell, fontName="Times-Bold")
code = ParagraphStyle("code", fontName="Courier", fontSize=8, leading=9.6)
ref = ParagraphStyle("ref", parent=body, firstLineIndent=-0.5 * inch, leftIndent=0.5 * inch)
step = ParagraphStyle("step", parent=body, firstLineIndent=-0.25 * inch, leftIndent=0.5 * inch)


def P(text, style=body):
    return Paragraph(text, style)


def H1(text):
    """Heading that moves to the next page when less than 1.1 inch remains."""
    return [CondPageBreak(0.9 * inch), Paragraph(text, h1)]


def code_block(text):
    tbl = Table([[Preformatted(text.strip("\n"), code)]], colWidths=[6.5 * inch])
    tbl.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F3F4F6")),
                             ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#9CA3AF")),
                             ("LEFTPADDING", (0, 0), (-1, -1), 6), ("TOPPADDING", (0, 0), (-1, -1), 4),
                             ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
    return tbl


def grid(rows, widths, header_bg="#E5E7EB"):
    data = [[Paragraph(str(c), cellb if r == 0 else cell) for c in row] for r, row in enumerate(rows)]
    tbl = Table(data, colWidths=[w * inch for w in widths], repeatRows=1)
    tbl.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#9CA3AF")),
                             ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(header_bg)),
                             ("VALIGN", (0, 0), (-1, -1), "TOP"),
                             ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                             ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3)]))
    return tbl


def footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Times-Roman", 10)
    canvas.drawRightString(7.5 * inch, 10.5 * inch, str(doc.page))
    canvas.restoreState()


# ---------------------------------------------------------------- numbers used in the text
kw_t, ai_t = T["keyword_baseline"], T["ai_with_threshold"]
kw_h, raw_h, ai_h = H["keyword_baseline"], H["ai_no_threshold"], H["ai_with_threshold"]
n_h = kw_h["n"]
kw_mis_t = round(kw_t["misroute_rate"] * T["keyword_baseline"]["n"])
raw_mis_h = round(raw_h["misroute_rate"] * n_h)
auto_h = round(ai_h["auto_route_rate"] * n_h)
esc_h = H["escalated_count"]
kw_correct_h = round(kw_h["accuracy"] * n_h)
needed = kw_correct_h - auto_h + 1  # correct Bedrock answers needed to beat keywords
unrouted_h = 1 - kw_h["auto_route_rate"]

story = []

# ---------------------------------------------------------------- title page
story += [Spacer(1, 2.2 * inch),
          P("AI-Assisted Incident Classification for Cloud Security Automation", title),
          P("Unit 6 Assignment: Choose-Your-Own AI Enhancement Project", center),
          P("Scenario 2: Automated Incident Classification", center),
          Spacer(1, 0.4 * inch),
          P("Clevon", center),
          P("CLCS 605 Cloud Architecture", center),
          P("University of Maryland Global Campus", center),
          P("September 2026", center),
          Spacer(1, 0.4 * inch),
          P(f"Code repository: {REPO}", center),
          P("Implementation artifacts: Unit6_AI_Incident_Classifier_Artifacts.zip", center),
          PageBreak()]

# ---------------------------------------------------------------- 1
story += [*H1("Problem Statement and Business Case"),
          P("Most AWS accounts route alerts with static rules. An EventBridge pattern or a ticketing rule matches a "
            "keyword and forwards the alert to a queue. Alerts written in unfamiliar words match no rule and wait for "
            "manual triage. Alerts carrying a misleading keyword reach the wrong team. Both failures stretch the time "
            "between detection and response, the phase NIST SP 800-61r3 ties most closely to incident impact "
            "(Nelson et al., 2025)."),
          P("This project adds a natural language processing (NLP) decision point to an EventBridge, SQS, and Lambda "
            "workflow. The function reads each Security Hub, GuardDuty, AWS Config, CloudWatch, or manually filed "
            "alert, assigns one of five categories, and notifies the owning team with a runbook. "
            "Four success criteria were fixed before testing: (a) zero misroutes among alerts the system "
            "routes on its own, (b) higher routing accuracy than a keyword baseline, (c) under 1 ms of local "
            "classification time per alert, and (d) every rubric security control enforced in code."),
          P(f"The business case rests on analyst time. Assume 400 alerts per day and 5 minutes of human triage for "
            f"each alert the automation fails to route. The keyword baseline in this study left {pct(unrouted_h)} of "
            f"unfamiliar alerts unrouted. Cutting the manual share by 20 points returns about 6.7 analyst hours per "
            f"day (400 x 0.20 x 5 minutes). Escalations to Claude Haiku 4.5, priced at $1 and $5 per million input and "
            f"output tokens (Anthropic, 2025), cost roughly 12 cents per 100 alerts at 900 input and 50 output "
            f"tokens each."),
          P("The design builds on published work. Nowak-Brzezinska and Drabek (2025) deployed a keyword-rule tier "
            "with a TF-IDF logistic regression fallback on AWS Lambda, S3, and DynamoDB, and the hybrid beat each "
            "standalone model on roughly 12,000 English support tickets. Palo Alto Networks classifies more than 200 "
            "million log entries per day with Claude Haiku on Amazon Bedrock and reports 95% precision and an 83% cut "
            "in incident response time (Amazon Web Services [AWS], 2026). This project combines both patterns.")]

# ---------------------------------------------------------------- 2
story += [*H1("Solution Architecture"),
          P("Figure 1 traces one alert through eight numbered steps. Five sources feed a single EventBridge rule (1), "
            "which delivers to an SQS queue encrypted with the project customer managed key, or CMK (2). A queue "
            "policy accepts messages from this rule's ARN alone. Three failed attempts move a message to a "
            "dead-letter queue and page SecOps."),
          KeepTogether([Image(str(ROOT / "results" / "architecture.png"), width=6.5 * inch, height=3.55 * inch),
                        P("Figure 1. Alert flow through the AI-enhanced pipeline. Numbers follow one alert from intake "
                          "to team notification. One KMS key encrypts every queue, table, topic, bucket, and log.",
                          caption)]),
          P("The Lambda classifier (3) runs in two private subnets with no internet gateway and no NAT gateway, so "
            "VPC endpoints (4) provide the only paths out (AWS, n.d.-c). Through them the function loads the model "
            "from S3 (5), escalates low-confidence alerts to Bedrock (6), records each decision in DynamoDB (7), and "
            "notifies the owning team through SNS (8). Endpoint policies limit each path to this project's resources. "
            "Config compliance changes feed the same rule, so the workflow also classifies drift in its own controls.")]

# ---------------------------------------------------------------- 3
story += [*H1("AI Models and Implementation"),
          P(f"Classification runs in two tiers. Tier 1 is a TF-IDF vectorizer over unigrams and bigrams feeding a "
            f"multinomial logistic regression model (Manning et al., 2008, and Pedregosa et al., 2011). A normalizer "
            f"collapses instance IDs, IP addresses, and key IDs into placeholder tokens such as <i>sgid</i> and "
            f"<i>adminport</i>. Five-fold "
            f"cross-validation on 1,200 training alerts selected C = {MODEL['C']:g} by lowest log loss. Training "
            f"exports {len(MODEL['features']):,} feature weights to model.json. A pure-Python scorer inside the "
            f"function matches scikit-learn probabilities to within 1e-9, so the deployment package carries no "
            f"third-party libraries."),
          P("Tier 2 handles uncertainty. When the top Tier 1 probability falls below 0.60, the function calls Claude "
            "Haiku 4.5 (inference profile us.anthropic.claude-haiku-4-5-20251001-v1:0) through the Bedrock Converse API "
            "(AWS, n.d.-b, n.d.-f). Code Sample 1 shows the decision logic from "
            "src/handler.py."),
          CondPageBreak(2.3 * inch), P("Code Sample 1. Two-tier decision with fail-closed fallback", label),
          code_block('''
def classify(text: str) -> dict:
    threshold = float(os.environ.get("CONFIDENCE_THRESHOLD", "0.60"))
    label, conf = load_model().predict(text)          # SHA-256 verified at cold start
    decision = {"category": label, "confidence": round(conf, 4), "tier": "local_model"}
    if conf < threshold:
        llm = llm_fallback.classify(client("bedrock-runtime"),
                                    os.environ["BEDROCK_MODEL_ID"], text)
        if llm:                                        # enum-validated answer
            decision.update(category=llm["category"], tier="bedrock", local_guess=label)
        else:                                          # error, timeout, or invalid output
            decision.update(category="MANUAL_TRIAGE", tier="fallback_manual")
    return decision'''),
          Spacer(1, 6),
          P("The Bedrock request forces one tool whose input schema allows only the five category names (Code Sample "
            "2) at temperature 0. The function checks the answer against the enum again. The model never writes "
            "remediation steps. Runbook text comes from a static catalog reviewed by engineers."),
          CondPageBreak(1.7 * inch), P("Code Sample 2. Enum-bound tool configuration from src/llm_fallback.py", label),
          code_block('''
TOOL_CONFIG = {
    "tools": [{"toolSpec": {"name": "record_classification",
        "inputSchema": {"json": {"type": "object", "properties": {
            "category":   {"type": "string", "enum": CATEGORIES},
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
            "rationale":  {"type": "string", "maxLength": 300}},
            "required": ["category", "confidence", "rationale"]}}}}],
    "toolChoice": {"tool": {"name": "record_classification"}},   # no free-text reply
}'''),
          Spacer(1, 6),
          P("DynamoDB stores each decision with a 90-day TTL, and a conditional write blocks duplicate notifications "
            "when SQS redelivers a message.")]

# ---------------------------------------------------------------- 4
story += [*H1("Security Controls and Threat Model"),
          P("The threat model covers five attack surfaces. Prompt injection comes first, since instance names, tags, "
            "and finding text reach the model and an attacker controls some of those fields (OWASP Foundation, 2025). "
            "The enum-bound tool call limits the worst outcome to one misrouted alert. Exfiltration has no path: the subnets have no internet route, and endpoint "
            "policies accept project ARNs alone. Privilege escalation fails because the role holds no IAM, KMS "
            "administration, or wildcard data actions. Model tampering fails because the function hashes model.json at "
            "cold start and refuses to score on a mismatch with the value pinned at deploy time. Bedrock runs for "
            "low-confidence alerts alone, and a reserved concurrency parameter caps spend during alert storms. Table 1 maps nine controls to the AWS Well-Architected Security Pillar (AWS, n.d.-a) and "
            "the CIS AWS Foundations Benchmark v3.0.0 (Center for Internet Security [CIS], 2024). CIS requirement numbers "
            "follow the AWS mapping for Security Hub CSPM (AWS, n.d.-e), and each Config rule comes from the AWS "
            "managed rule list (AWS, n.d.-d)."),
          CondPageBreak(1.0 * inch), P("Table 1. Control mapping to frameworks, lab components, and evidence", label),
          grid([
              ["Control", "Framework reference", "Implementation in this lab", "Evidence"],
              ["Least privilege", "WA SEC03-BP02, CIS 1.16 (no full *:* admin policies)",
               "Role with 8 scoped statements. ENI actions on * are the only wildcard (AWS requirement). Config rule "
               "iam-policy-no-admin-access.", "E1, E8"],
              ["Key management", "WA SEC08-BP01, CIS 3.6 (CMK rotation)",
               "One CMK, rotation on, 7-day deletion window. Role uses the key through kms:ViaService for five services.",
               "E2"],
              ["Encryption at rest", "WA SEC08-BP02",
               "CMK on SQS, DLQ, SNS, DynamoDB, S3 (bucket key), Lambda env vars, CloudWatch Logs.", "E3, E6, E7"],
              ["Encryption in transit", "WA SEC09-BP02, CIS 2.1.1 (deny HTTP)",
               "Bucket and queue policies deny aws:SecureTransport = false. All endpoints on TCP 443.", "E3"],
              ["Public access block", "CIS 2.1.4 (Block Public Access)",
               "All four block settings on, ObjectOwnership BucketOwnerEnforced.", "E3, E8"],
              ["Network traffic control", "WA SEC05-BP02",
               "Private subnets, no IGW or NAT. SG chaining: lambda-sg egress 443 to endpoint-sg, endpoint-sg ingress 443 "
               "from lambda-sg. Endpoint policies scoped to project ARNs.", "E4, E5"],
              ["Default SG closed", "CIS 5.4",
               "deploy.sh revokes every default SG rule. Config rule vpc-default-security-group-closed.", "E4, E8"],
              ["Configuration monitoring", "CIS 3.3 (AWS Config enabled), WA SEC04-BP01",
               "Recorder with KMS-encrypted delivery. 10 managed rules. Optional Security Hub CSPM with CIS v3.0.0.",
               "E8"],
              ["Network logging", "CIS 3.7 (VPC flow logs)",
               "ALL-traffic flow logs to the SSE-KMS bucket, 365-day lifecycle.", "E5"],
          ], [1.05, 1.45, 3.35, 0.65])]

# ---------------------------------------------------------------- 5
story += [*H1("Deployment Instructions"),
          P("Deployment runs in AWS CloudShell (us-east-1), which includes the AWS CLI.", noindent)]
steps = [
    "Submit the one-time Anthropic use-case form in Amazon Bedrock. New accounts also need a nonzero daily token quota.",
    "In CloudShell, upload the repository and run ALERT_EMAIL=you@example.com ./scripts/deploy.sh.",
    "Confirm the SNS subscription email.",
    "Run ./scripts/send_test_events.sh, then ./scripts/verify_controls.sh for evidence E1 through E8.",
    "Run ./scripts/teardown.sh after grading. At $0.01 per endpoint per Availability Zone hour (AWS, n.d.-g), the "
    "two interface endpoints cost about $0.96 per day.",
]
story += [P(f"{i}.&nbsp;&nbsp;{s}", step) for i, s in enumerate(steps, 1)]

# ---------------------------------------------------------------- 6
story += [*H1("Evaluation Methodology and Results"),
          P("The offline test script training/evaluate.py scores two routers with the same code path the function "
            "runs. The keyword baseline applies ordered substring rules, first match wins, and sends unmatched alerts "
            "to manual triage. Two held-out sets were used. The test set holds 300 alerts from the training template "
            "families with new values and a 25% rate of distractor sentences. The hard set holds 150 alerts written in "
            "help-desk language from templates absent from training. No labeled alert history from a production "
            "account was available, so all data are synthetic and regenerate from seed 605. Table 2 reports accuracy (correct team), auto-routed share, misroute rate, and macro-F1."),
          CondPageBreak(1.6 * inch), P("Table 2. Routing results on held-out data", label),
          grid([
              ["Data set", "Router", "Accuracy", "Auto-routed", "Misrouted", "Macro-F1"],
              ["Test (n=300)", "Keyword rules", pct(kw_t["accuracy"]), pct(kw_t["auto_route_rate"]),
               pct(kw_t["misroute_rate"]), f"{kw_t['macro_f1']:.3f}"],
              ["Test (n=300)", "Tier 1, gate 0.60", pct(ai_t["accuracy"]), pct(ai_t["auto_route_rate"]),
               pct(ai_t["misroute_rate"]), f"{ai_t['macro_f1']:.3f}"],
              ["Hard (n=150)", "Keyword rules", pct(kw_h["accuracy"]), pct(kw_h["auto_route_rate"]),
               pct(kw_h["misroute_rate"]), f"{kw_h['macro_f1']:.3f}"],
              ["Hard (n=150)", "Tier 1, no gate", pct(raw_h["accuracy"]), pct(raw_h["auto_route_rate"]),
               pct(raw_h["misroute_rate"]), f"{raw_h['macro_f1']:.3f}"],
              ["Hard (n=150)", "Tier 1, gate 0.60", pct(ai_h["accuracy"]), pct(ai_h["auto_route_rate"]),
               pct(ai_h["misroute_rate"]), f"{ai_h['macro_f1']:.3f}"],
          ], [1.0, 1.45, 0.95, 1.05, 1.0, 1.05]),
          Spacer(1, 8),
          P(f"On familiar wording, Tier 1 removed all {kw_mis_t} keyword misroutes. Distractor sentences caused them, "
            f"such as a CPU alarm on an instance behind a named security group. On unfamiliar "
            f"wording, Tier 1 without a gate reached {pct(raw_h['accuracy'])} accuracy, nearly double the keyword "
            f"router, but sent {raw_mis_h} alerts to the wrong team. The 0.60 gate converted every one of those "
            f"misroutes into an escalation: {auto_h} alerts routed with zero errors and {esc_h} went to Bedrock. "
            f"All 15 unit tests pass."),
          P(f"The live deployment on September 27, 2026 built all 45 resources on the first attempt. Six test alerts "
            f"and one real Config finding reached DynamoDB (Appendix A, E9). Five clear alerts routed on Tier 1 at 0.98 "
            f"to 0.996 confidence. The prompt-injection alert routed to THREAT_DETECTION at 0.988 and never reached "
            f"Bedrock. With the new account's daily Bedrock quota at zero, the low-confidence firewall alert failed "
            f"closed to MANUAL_TRIAGE. Criteria (a), (c), and (d) pass. "
            f"Criterion (b) passes on the test set, and on the hard set once Bedrock labels {needed} of {esc_h} "
            f"escalations correctly, pending a quota fix from AWS Support.")]

# ---------------------------------------------------------------- 7
story += [*H1("Challenges and Resolutions"),
          P("Macro-F1 read 1.000 for every C value on near-separable data, so log loss became the selection metric. "
            "The live Config rules also caught two real gaps. The CLI-built staging bucket lacked a TLS-only policy, and "
            "Config flagged the bucket within minutes. A bucket policy fixed the finding, and deploy.sh now applies the "
            "policy at creation. Config also flagged the unused default VPC for open default security group rules and "
            "missing flow logs. Deleting the VPC cleared the flow log finding. One stale result remains for a security "
            "group AWS reports as nonexistent (E8b, E8c).")]

story += [*H1("Recommendations for Future Improvements"),
          P("Retrain monthly on labeled production alerts, and add Bedrock Guardrails, a permissions boundary, and "
            "Lambda code signing. After 30 days of perfect Tier 1 precision on one narrow class, attach a quarantine "
            "runbook gated by one-click human approval.")]

# ---------------------------------------------------------------- references
story += [PageBreak(), *H1("References")]
refs = [
    "Amazon Web Services. (2026). <i>How Palo Alto Networks enhanced device security infra log analysis with Amazon "
    "Bedrock</i>. AWS Machine Learning Blog. https://aws.amazon.com/blogs/machine-learning/how-palo-alto-networks-"
    "enhanced-device-security-infra-log-analysis-with-amazon-bedrock",
    "Amazon Web Services. (n.d.-a). <i>Security pillar: AWS Well-Architected Framework</i>. Retrieved September 23, "
    "2026, from https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html",
    "Amazon Web Services. (n.d.-b). <i>Carry out a conversation with the Converse API operations</i>. Amazon Bedrock "
    "User Guide. Retrieved September 23, 2026, from https://docs.aws.amazon.com/bedrock/latest/userguide/conversation-inference.html",
    "Amazon Web Services. (n.d.-c). <i>Giving Lambda functions access to resources in an Amazon VPC</i>. AWS Lambda "
    "Developer Guide. Retrieved September 23, 2026, from https://docs.aws.amazon.com/lambda/latest/dg/configuration-vpc.html",
    "Amazon Web Services. (n.d.-d). <i>List of AWS Config managed rules</i>. AWS Config Developer Guide. Retrieved "
    "September 23, 2026, from https://docs.aws.amazon.com/config/latest/developerguide/managed-rules-by-aws-config.html",
    "Amazon Web Services. (n.d.-e). <i>CIS AWS Foundations Benchmark in Security Hub CSPM</i>. AWS Security Hub User "
    "Guide. Retrieved September 23, 2026, from https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html",
    "Amazon Web Services. (n.d.-f). <i>Claude Haiku 4.5</i>. Amazon Bedrock User Guide. Retrieved September 23, 2026, "
    "from https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-anthropic-claude-haiku-4-5.html",
    "Amazon Web Services. (n.d.-g). <i>AWS PrivateLink pricing</i>. Retrieved September 23, 2026, from "
    "https://aws.amazon.com/privatelink/pricing/",
    "Anthropic. (2025, October 15). <i>Introducing Claude Haiku 4.5</i>. https://www.anthropic.com/news/claude-haiku-4-5",
    "Center for Internet Security. (2024). <i>CIS Amazon Web Services Foundations Benchmark v3.0.0</i>. "
    "https://www.cisecurity.org/benchmark/amazon_web_services",
    "Manning, C. D., Raghavan, P., &amp; Sch\u00fctze, H. (2008). <i>Introduction to information retrieval</i>. "
    "Cambridge University Press.",
    "Nelson, A., Rekhi, S., Souppaya, M., &amp; Scarfone, K. (2025). <i>Incident response recommendations and "
    "considerations for cybersecurity risk management: A CSF 2.0 community profile</i> (NIST SP 800-61r3). National "
    "Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-61r3",
    "Nowak-Brzezinska, A., &amp; Drabek, D. (2025). A hybrid knowledge-based machine learning approach for ticket "
    "classification in the AWS cloud. <i>Procedia Computer Science, 270</i>, 4796-4803. "
    "https://doi.org/10.1016/j.procs.2025.09.605",
    "OWASP Foundation. (2025). <i>LLM01:2025 prompt injection</i>. OWASP Top 10 for LLM Applications. "
    "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
    "Pedregosa, F., Varoquaux, G., Gramfort, A., Michel, V., Thirion, B., Grisel, O., Blondel, M., Prettenhofer, P., "
    "Weiss, R., Dubourg, V., Vanderplas, J., Passos, A., Cournapeau, D., Brucher, M., Perrot, M., &amp; Duchesnay, "
    "\u00c9. (2011). Scikit-learn: Machine learning in Python. <i>Journal of Machine Learning Research, 12</i>, 2825-2830.",
]
story += [P(r, ref) for r in refs]

# ---------------------------------------------------------------- appendix A
story += [PageBreak(), *H1("Appendix A: Evidence Index"),
          P("Each control in Table 1 traces to a resource in infra/template.yaml and to a read-only check in "
            "scripts/verify_controls.sh. Screenshots of each check follow the index.", noindent),
          grid([
              ["ID", "Evidence", "Template resource(s)", "Check"],
              ["E1", "IAM role inline policy", "ClassifierRole", "aws iam get-role-policy"],
              ["E2", "CMK state and rotation", "AppKey, AppKeyAlias", "aws kms get-key-rotation-status"],
              ["E3", "S3 SSE-KMS, public access block, TLS-only policy", "ArtifactBucket, ArtifactBucketPolicy",
               "s3api get-bucket-encryption / get-public-access-block / get-bucket-policy"],
              ["E4", "Security group chaining", "LambdaSecurityGroup, EndpointSecurityGroup, LambdaToEndpointEgress, "
               "EndpointFromLambdaIngress", "ec2 describe-security-groups"],
              ["E5", "Endpoints, no IGW or NAT, flow logs", "S3GatewayEndpoint, DynamoDbGatewayEndpoint, "
               "BedrockRuntimeEndpoint, SnsEndpoint, VpcFlowLog", "ec2 describe-vpc-endpoints / describe-flow-logs"],
              ["E6", "Lambda VPC placement, env encryption", "ClassifierFunction", "lambda get-function-configuration"],
              ["E7", "DynamoDB and SNS encryption", "IncidentTable, SecOpsTopic, NetOpsTopic, CloudOpsTopic",
               "dynamodb describe-table / sns get-topic-attributes"],
              ["E8", "Config recorder and rule compliance", "Rule* (10), config-recorder.yaml",
               "configservice describe-compliance-by-config-rule"],
              ["E8b, E8c", "Stale default VPC security group finding", "Deleted default VPC",
               "get-compliance-details / describe-security-groups"],
              ["E9", "Pipeline output", "IncidentRule, IncidentQueue, QueueToFunction", "send_test_events.sh"],
              ["E5b, E10", "Single VPC, root MFA", "Account hardening", "VPC and IAM consoles"],
          ], [0.4, 1.9, 2.4, 1.8])]

EVIDENCE = [
    ("E1", "IAM role inline policy, classifier-least-privilege (full policy in verify_controls.sh output)"),
    ("E2", "Customer managed KMS key aic-data, automatic rotation enabled, 365-day period"),
    ("E3", "Artifacts bucket: Block Public Access on and TLS-only bucket policy"),
    ("E4", "Lambda security group: zero inbound rules, three outbound HTTPS rules to the endpoint group and prefix lists"),
    ("E5", "Four VPC endpoints available: bedrock-runtime, sns, dynamodb, s3"),
    ("E5b", "Single VPC in the Region after deleting the unused default VPC"),
    ("E6", "Lambda attached to two private subnets in aic-vpc with aic-lambda-sg (browser profile tooltip redacted)"),
    ("E7", None),
    ("E8", "AWS Config rules: eight compliant, one without applicable resources, one stale finding"),
    ("E8b", "Stale finding: live default group COMPLIANT, deleted group still recorded as ResourceDiscovered"),
    ("E8c", "AWS confirms the flagged security group no longer exists"),
    ("E9", "DynamoDB decision log after the live test run"),
    ("E10", "Root user MFA assigned, zero root access keys (email redacted)"),
]
E7_TEXT = """=== E7  DynamoDB and SNS encryption ===
{
    "Status": "ENABLED",
    "SSEType": "KMS",
    "KMSMasterKeyArn":
      "arn:aws:kms:us-east-1:020651500161:key/e3fe15e5-a88d-4e51-a77a-9ac60e8da291"
}
e3fe15e5-a88d-4e51-a77a-9ac60e8da291      (aic-secops topic KMS key)
e3fe15e5-a88d-4e51-a77a-9ac60e8da291      (aic-netops topic KMS key)
e3fe15e5-a88d-4e51-a77a-9ac60e8da291      (aic-cloudops topic KMS key)"""
from PIL import Image as PILImage
for eid, text in EVIDENCE:
    if eid == "E7":
        story.append(KeepTogether([Spacer(1, 8), code_block(E7_TEXT),
                                   P("Evidence E7. DynamoDB and SNS encryption, CloudShell output from "
                                     "verify_controls.sh.", caption)]))
        continue
    img = ROOT / "evidence" / f"{eid}.png"
    if img.exists():
        w, h = PILImage.open(img).size
        width = 6.5 * inch
        height = min(width * h / w, 8.0 * inch)
        story.append(KeepTogether([Spacer(1, 8), Image(str(img), width=height * w / h, height=height),
                                   P(f"Screenshot {eid}. {text}.", caption)]))

doc = SimpleDocTemplate(str(OUT), pagesize=letter, leftMargin=inch, rightMargin=inch, topMargin=inch,
                        bottomMargin=inch, title="AI-Assisted Incident Classification", author="Clevon")
doc.build(story, onFirstPage=lambda c, d: None, onLaterPages=footer)
print(f"wrote {OUT}")
