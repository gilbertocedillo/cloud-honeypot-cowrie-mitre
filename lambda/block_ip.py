"""
Block-IP Lambda - Intelligent Cloud Honeypot
Invoked by n8n ONLY after the deterministic gate passes
(VirusTotal malicious threshold OR confirmed payload-download behavior).

====================================================================
WHY NOT "ADD A DENY RULE TO THE SECURITY GROUP"?
Security Groups have NO deny rules. They are allow-only and stateful:
if traffic is not matched by an allow, it is dropped - but you cannot
carve an exception that says "allow 22 from everyone EXCEPT this IP".
So the technically correct blocking patterns on AWS are:

  1) Network ACL DENY entry  (this Lambda, primary)
     NACLs are stateless and DO support explicit deny. Rules evaluate
     in numeric order, so deny rules are inserted at low numbers
     (10..999, capacity-aware) and the baseline ALLOW rules must live
     at 1000+ in production. This repo's Terraform baseline uses
     100/110 for the lab, so Lambda denies allocate 10..99 first and
     then extend; see allocate_rule_no() and keep ranges in sync.

  2) AWS WAF IP set  (this Lambda, secondary)
     If any real service sits behind an ALB / API Gateway / CloudFront
     with a WAF, adding the IP to the blocklist IP set blocks it at
     the edge too. Optional - runs only when WAF_IPSET_ID is set.

Idempotency: an IP already denied (NACL) or already in the IP set is
reported as already_blocked, never duplicated. CIDR is always /32.
====================================================================
"""
import json, os, ipaddress
import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timezone

ec2 = boto3.client("ec2")
waf = boto3.client("wafv2")

NACL_ID = os.environ.get("NACL_ID", "")
WAF_IPSET_ID = os.environ.get("WAF_IPSET_ID", "")
WAF_IPSET_NAME = os.environ.get("WAF_IPSET_NAME", "")
WAF_SCOPE = os.environ.get("WAF_SCOPE", "REGIONAL")
DRY_RUN = os.environ.get("DRY_RUN", "true").lower() == "true"
MAX_BLOCKED = int(os.environ.get("MAX_BLOCKED_IPS", "900"))
# Deny rule numbers are allocated from this range (lowest free wins)
RULE_RANGE = range(10, 1000)

def valid_ipv4(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).version == 4
    except Exception:
        return False

def nacl_current() -> dict:
    """Return {cidr: rule_no} for existing DENY entries + set of used rule numbers."""
    resp = ec2.describe_network_acls(NetworkAclIds=[NACL_ID])
    entries = resp["NetworkAcls"][0].get("Entries", [])
    denies, used = {}, set()
    for e in entries:
        used.add(e["RuleNumber"])
        if not e.get("Egress") and e.get("RuleAction") == "deny":
            denies[e["CidrBlock"]] = e["RuleNumber"]
    return denies, used

def allocate_rule_no(used: set) -> int | None:
    for n in RULE_RANGE:
        if n not in used:
            return n
    return None

def block_nacl(ip: str) -> dict:
    cidr = f"{ip}/32"
    denies, used = nacl_current()
    if cidr in denies:
        return {"layer": "nacl", "status": "already_blocked", "rule_no": denies[cidr], "cidr": cidr}
    if len(denies) >= MAX_BLOCKED:
        return {"layer": "nacl", "status": "capacity_reached", "blocked_count": len(denies)}
    rule_no = allocate_rule_no(used)
    if rule_no is None:
        return {"layer": "nacl", "status": "no_free_rule_number"}
    if not DRY_RUN:
        ec2.create_network_acl_entry(
            NetworkAclId=NACL_ID, RuleNumber=rule_no, Protocol="-1",
            RuleAction="deny", Egress=False, CidrBlock=cidr,
        )
    return {"layer": "nacl", "status": "blocked" if not DRY_RUN else "dry_run_would_block",
            "rule_no": rule_no, "cidr": cidr}

def block_waf(ip: str) -> dict:
    if not WAF_IPSET_ID or not WAF_IPSET_NAME:
        return {"layer": "waf", "status": "skipped_not_configured"}
    cidr = f"{ip}/32"
    ipset = waf.get_ip_set(Name=WAF_IPSET_NAME, Scope=WAF_SCOPE, Id=WAF_IPSET_ID)["IPSet"]
    addrs = ipset.get("Addresses", [])
    if cidr in addrs:
        return {"layer": "waf", "status": "already_blocked", "cidr": cidr}
    # Optimistic locking: re-read LockToken immediately before update
    fresh = waf.get_ip_set(Name=WAF_IPSET_NAME, Scope=WAF_SCOPE, Id=WAF_IPSET_ID)
    if not DRY_RUN:
        waf.update_ip_set(
            Name=WAF_IPSET_NAME, Scope=WAF_SCOPE, Id=WAF_IPSET_ID,
            Addresses=addrs + [cidr], LockToken=fresh["LockToken"],
        )
    return {"layer": "waf", "status": "blocked" if not DRY_RUN else "dry_run_would_block", "cidr": cidr}

def handler(event, context):
    body = event if isinstance(event, dict) else {}
    if isinstance(event.get("body"), str):
        try: body = json.loads(event["body"])
        except Exception: pass

    ip = str(body.get("source_ip") or body.get("ip") or "").strip()
    reason = body.get("reason", "honeypot_confirmed_attacker")
    severity = body.get("severity", "unknown")

    if not valid_ipv4(ip):
        return resp(400, {"ok": False, "error": "valid IPv4 source_ip required"})
    if not NACL_ID:
        return resp(500, {"ok": False, "error": "NACL_ID env var not set"})

    results = []
    try:
        results.append(block_nacl(ip))
    except ClientError as e:
        results.append({"layer": "nacl", "status": "error", "error": str(e)})
    try:
        results.append(block_waf(ip))
    except ClientError as e:
        results.append({"layer": "waf", "status": "error", "error": str(e)})

    result = {
        "ok": True, "action": "block_ip", "source_ip": ip,
        "severity": severity, "reason": reason, "dry_run": DRY_RUN,
        "results": results,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    print(json.dumps(result))  # CloudWatch forensic trail
    return resp(200, result)

def resp(code, body):
    return {"statusCode": code, "headers": {"Content-Type": "application/json"},
            "body": json.dumps(body)}

# UNBLOCK (manual, intentional - never automatic):
# aws ec2 delete-network-acl-entry --network-acl-id acl-xxx --rule-number <n> --ingress
# and remove the /32 from the WAF IP set (wafv2 update-ip-set).
