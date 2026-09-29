"""
generate_dataset.py
Builds a labeled, synthetic alert corpus modeled on the wording of AWS Security
Hub, GuardDuty, AWS Config, and CloudWatch alarm notifications.

Outputs (JSON Lines, one {"text", "label", "source"} record per line):
  data/alerts_train.jsonl  1,200 records (240 per class), template set A
  data/alerts_test.jsonl     300 records (60 per class), template set A, new fills
  data/alerts_hard.jsonl     150 records (30 per class), template set B only

Template set B holds free-text, human-written phrasings (help desk tickets,
chat messages) that never appear in training. The hard set measures how the
model behaves on wording nobody planned for.

Run:  python training/generate_dataset.py      (seed fixed at 605 for repeatability)
"""
import json
import random
from pathlib import Path

SEED = 605
OUT = Path(__file__).resolve().parent.parent / "data"

CLASSES = ["IDENTITY_ACCESS", "NETWORK_EXPOSURE", "DATA_PROTECTION",
           "COMPUTE_AVAILABILITY", "THREAT_DETECTION"]


def rid(prefix, n=17):
    return f"{prefix}-" + "".join(random.choice("0123456789abcdef") for _ in range(n))


def ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


FILL = {
    "user": lambda: random.choice(["jsmith", "svc-backup", "deploy-bot", "a.garcia", "ci-runner", "mbrown", "etl-user"]),
    "role": lambda: random.choice(["ProdDeployRole", "DataPipelineRole", "ReadOnlyAudit", "BreakGlassAdmin", "LambdaExecRole"]),
    "policy": lambda: random.choice(["DevFullAccess", "LegacyOpsPolicy", "TempAdmin", "VendorAccess"]),
    "key": lambda: "AKIA" + "".join(random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(16)),
    "days": lambda: str(random.choice([91, 120, 180, 240, 400, 730])),
    "country": lambda: random.choice(["Romania", "Brazil", "Vietnam", "Nigeria", "Russia", "Netherlands"]),
    "api": lambda: random.choice(["CreateAccessKey", "PutBucketPolicy", "StopLogging", "ListBuckets", "AttachUserPolicy"]),
    "sg": lambda: rid("sg", 8), "i": lambda: rid("i"), "vpc": lambda: rid("vpc", 8),
    "nacl": lambda: rid("acl", 8), "rt": lambda: rid("rtb", 8), "vol": lambda: rid("vol"),
    "snap": lambda: rid("snap"),
    "port": lambda: str(random.choice([22, 3389, 3306, 5432, 1433, 445, 23])),
    "ip": ip,
    "lb": lambda: random.choice(["web-alb-prod", "api-nlb", "portal-alb"]),
    "bucket": lambda: random.choice(["acme-invoices", "hr-exports-prod", "clickstream-raw", "backup-archive-01", "static-web-assets"]),
    "db": lambda: random.choice(["orders-db", "reporting-replica", "payroll-postgres", "crm-mysql"]),
    "kms": lambda: random.choice(["alias/app-data", "alias/backup", "alias/payroll"]),
    "table": lambda: random.choice(["Sessions", "Orders", "AuditTrail"]),
    "fn": lambda: random.choice(["order-processor", "thumbnail-gen", "etl-loader", "auth-callback"]),
    "asg": lambda: random.choice(["web-asg", "worker-asg", "batch-asg"]),
    "svc": lambda: random.choice(["checkout-svc", "search-api", "notifier"]),
    "tg": lambda: random.choice(["tg-web-80", "tg-api-8080"]),
    "pct": lambda: str(random.randint(85, 99)),
    "n": lambda: str(random.randint(3, 400)),
    "domain": lambda: random.choice(["xmr.pool-miner.net", "update-check.cc", "cdn-sync.top", "a8f2k.duckdns.org"]),
    "region": lambda: random.choice(["us-east-1", "us-west-2", "eu-west-1"]),
    "acct": lambda: str(random.randint(100000000000, 999999999999)),
    "sev": lambda: random.choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
    "env": lambda: random.choice(["prod", "staging", "dev"]),
}

# Wrappers reproduce the boilerplate each AWS source adds. The same wrappers
# appear across every class, so they teach the model nothing about category.
WRAPPERS = [
    "Security Hub finding: {t}. Severity {sev}. Account {acct} region {region}.",
    "GuardDuty finding: {t}. Severity {sev}.",
    "AWS Config rule NON_COMPLIANT: {t}.",
    "[ALARM] {t} in account {acct}",
    "{t}",
    "Incident report ({env}): {t}. Reported by on-call engineer.",
]

# Distractors put misleading words from other categories into an alert.
# Rule-based routers misfire on these. Example: a CPU alarm on an instance
# whose name mentions a security group.
DISTRACTORS = {
    "COMPUTE_AVAILABILITY": [" Instance sits behind security group {sg}.", " Host runs the IAM token service.",
                             " Data volume encrypted with KMS."],
    "DATA_PROTECTION": [" Bucket is attached to instance profile role {role}.", " Found during network review."],
    "NETWORK_EXPOSURE": [" Instance {i} also shows high CPU.", " Group owned by IAM team."],
    "IDENTITY_ACCESS": [" Activity touched S3 bucket {bucket}.", " Call originated inside VPC {vpc}."],
    "THREAT_DETECTION": [" Instance security group {sg} allows port 443.", " Instance role {role} attached."],
}

TEMPLATES_A = {
    "IDENTITY_ACCESS": [
        "IAM user {user} has console access without MFA enabled",
        "Root account used to call {api} from {ip}",
        "Access key {key} for user {user} has not been rotated in {days} days",
        "IAM policy {policy} grants full administrative privileges *:*",
        "Unusual AssumeRole activity for role {role} from a new ASN",
        "Password policy does not require a minimum length of 14 characters",
        "Credentials for {user} used from anomalous geolocation {country}",
        "Console login failures exceeded threshold for user {user}",
        "IAM user {user} has inline policy attached directly instead of through a group",
        "Unused credentials for {user} older than 45 days remain active",
    ],
    "NETWORK_EXPOSURE": [
        "Security group {sg} allows unrestricted ingress on port {port} from 0.0.0.0/0",
        "Network ACL {nacl} permits inbound SSH from any address",
        "EC2 instance {i} has a public IP and open RDP port 3389",
        "VPC {vpc} flow logs are not enabled",
        "Default security group of VPC {vpc} allows inbound and outbound traffic",
        "Load balancer {lb} listener accepts HTTP without redirect to HTTPS",
        "Route table {rt} sends 0.0.0.0/0 to an internet gateway from a private subnet",
        "Security group {sg} allows ingress from ::/0 on all ports",
        "VPC peering connection routes allow full CIDR access between {vpc} and partner VPC",
        "Subnet auto-assigns public IPv4 addresses in VPC {vpc}",
    ],
    "DATA_PROTECTION": [
        "S3 bucket {bucket} is publicly readable through bucket ACL",
        "S3 bucket {bucket} does not enforce server-side encryption",
        "RDS instance {db} storage is not encrypted",
        "KMS key {kms} automatic rotation is disabled",
        "EBS volume {vol} is unencrypted",
        "S3 bucket policy for {bucket} does not deny non-TLS requests",
        "Macie detected sensitive data (credit card numbers) in bucket {bucket}",
        "DynamoDB table {table} point-in-time recovery is disabled",
        "EBS snapshot {snap} is shared publicly",
        "RDS snapshot for {db} is not encrypted at rest",
    ],
    "COMPUTE_AVAILABILITY": [
        "CPUUtilization for {i} above {pct} percent for 15 minutes",
        "Lambda function {fn} error rate exceeded 5 percent",
        "EC2 status check failed for instance {i}",
        "Auto Scaling group {asg} failed to launch instances: insufficient capacity",
        "RDS {db} free storage space below 10 percent",
        "ECS service {svc} running task count below desired count",
        "Target group {tg} has {n} unhealthy hosts",
        "Memory utilization on {i} above {pct} percent",
        "Lambda function {fn} throttles exceeded threshold",
        "Disk usage on {i} root volume above {pct} percent",
    ],
    "THREAT_DETECTION": [
        "EC2 instance {i} is communicating with a known cryptocurrency mining pool",
        "Malware detected on EBS volume attached to {i}",
        "Port scan from {ip} against {i} detected",
        "Instance {i} querying domain {domain} associated with command and control",
        "DNS data exfiltration pattern detected from {i}",
        "Trojan activity: instance {i} contacted known malicious IP {ip}",
        "Brute force SSH attempts against {i} from {ip}",
        "Tor exit node communication observed from {i}",
        "Backdoor behavior: {i} is performing denial of service outbound",
        "Reverse shell pattern detected on {i} connecting to {ip}",
    ],
}

TEMPLATES_B = {
    "IDENTITY_ACCESS": [
        "someone logged in as the root user this morning, please check who",
        "service account keys for {user} are {days} days old and still in use",
        "the developers group can do everything in the account, admin policy is attached",
        "MFA is missing for {n} console users in {env}",
        "role session for {role} came from an address we have never seen before",
        "a login for {user} from {country} at 3am, user is on vacation",
    ],
    "NETWORK_EXPOSURE": [
        "port 22 is open to the whole internet on the bastion",
        "anyone outside can reach the database on port 5432",
        "no flow logging turned on for the new {env} VPC",
        "windows jump host has remote desktop exposed publicly",
        "firewall rule on the web tier lets every source in on every port",
        "private subnet now has a route out to the internet gateway",
    ],
    "DATA_PROTECTION": [
        "the bucket with customer invoices has public read on it",
        "snapshots of the {env} database are not encrypted",
        "customer master key auto rotation got turned off",
        "found social security numbers sitting in the log archive bucket",
        "backups copied to a bucket without default encryption",
        "someone shared a disk snapshot with the public",
    ],
    "COMPUTE_AVAILABILITY": [
        "app servers pegged at {pct}% CPU since the deploy",
        "container keeps restarting, desired 4 running 1",
        "disk almost full on the reporting database",
        "health checks failing behind the {lb}",
        "the {fn} function is timing out on most invocations",
        "scaling group cannot add capacity, launches keep failing",
    ],
    "THREAT_DETECTION": [
        "box {i} is talking to a mining pool",
        "outbound traffic to a known botnet controller from {i}",
        "hundreds of failed ssh logins from a single foreign address",
        "weird DNS TXT queries leaving {i}, looks like tunneling",
        "antivirus flagged a trojan on the file server",
        "instance is connecting to tor nodes at night",
    ],
}


def fill(template: str) -> str:
    out = template
    for key, fn in FILL.items():
        token = "{" + key + "}"
        while token in out:
            out = out.replace(token, fn(), 1)
    return out


def make(label: str, templates: dict, wrap: bool, distract_rate: float) -> dict:
    text = fill(random.choice(templates[label]))
    if random.random() < distract_rate:
        text += fill(random.choice(DISTRACTORS[label]))
    text = text.rstrip(".")
    if wrap:
        wrapper = random.choice(WRAPPERS)
        text = fill(wrapper.replace("{t}", text.replace("{", "(").replace("}", ")")))
    return {"text": text, "label": label}


def build(templates, per_class, wrap, distract_rate, source):
    rows = []
    for label in CLASSES:
        for _ in range(per_class):
            row = make(label, templates, wrap, distract_rate)
            row["source"] = source
            rows.append(row)
    random.shuffle(rows)
    return rows


def write(name, rows):
    OUT.mkdir(exist_ok=True)
    with open(OUT / name, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")
    print(f"wrote {len(rows):>5} rows -> data/{name}")


if __name__ == "__main__":
    random.seed(SEED)
    write("alerts_train.jsonl", build(TEMPLATES_A, 240, True, 0.25, "set_a"))
    write("alerts_test.jsonl", build(TEMPLATES_A, 60, True, 0.25, "set_a"))
    write("alerts_hard.jsonl", build(TEMPLATES_B, 30, False, 0.0, "set_b"))
