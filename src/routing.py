"""
routing.py
Maps a category to an owning team (SNS topic) and a remediation runbook.

Remediation text is static and reviewed by humans. Neither the classifier nor
the LLM writes remediation steps, which keeps attacker-controlled alert text
from reaching an engineer as a trusted instruction.
"""
import os

# Category -> environment variable holding the SNS topic ARN for the owner team.
TEAM_TOPIC_ENV = {
    "IDENTITY_ACCESS": "TOPIC_SECOPS",
    "THREAT_DETECTION": "TOPIC_SECOPS",
    "DATA_PROTECTION": "TOPIC_SECOPS",
    "NETWORK_EXPOSURE": "TOPIC_NETOPS",
    "COMPUTE_AVAILABILITY": "TOPIC_CLOUDOPS",
    "MANUAL_TRIAGE": "TOPIC_SECOPS",  # unclassifiable alerts default to security
}

RUNBOOKS = {
    "IDENTITY_ACCESS": [
        "Confirm the principal and source IP in CloudTrail for the last 24 hours.",
        "Disable or rotate the affected access key. Enforce MFA on the user.",
        "Replace wildcard policies with scoped actions. Review with IAM Access Analyzer.",
    ],
    "NETWORK_EXPOSURE": [
        "Remove 0.0.0.0/0 and ::/0 ingress on admin ports. Use SSM Session Manager instead of SSH/RDP.",
        "Reference security groups by ID instead of CIDR ranges between tiers.",
        "Enable VPC Flow Logs if missing and confirm no active sessions from untrusted IPs.",
    ],
    "DATA_PROTECTION": [
        "Enable S3 Block Public Access and remove public ACLs or snapshot shares.",
        "Turn on default SSE-KMS encryption and KMS key rotation.",
        "Run Amazon Macie on the resource if sensitive data exposure is possible.",
    ],
    "COMPUTE_AVAILABILITY": [
        "Check the CloudWatch metric history and the latest deployment for a correlated change.",
        "Scale out or roll back. Confirm Auto Scaling health checks and target group health.",
        "Open a problem record if the alarm fires more than twice in 24 hours.",
    ],
    "THREAT_DETECTION": [
        "Isolate the instance: swap in a quarantine security group with no rules.",
        "Snapshot EBS volumes for forensics before any termination.",
        "Rotate credentials reachable from the instance role. Follow the IR plan.",
    ],
    "MANUAL_TRIAGE": [
        "Automated classification failed or was low confidence. An analyst assigns the owner.",
    ],
}


def route(category: str) -> dict:
    """Return the topic ARN and runbook steps for a category."""
    if category not in RUNBOOKS:
        category = "MANUAL_TRIAGE"
    return {
        "category": category,
        "topic_arn": os.environ.get(TEAM_TOPIC_ENV[category], ""),
        "remediation": RUNBOOKS[category],
    }
