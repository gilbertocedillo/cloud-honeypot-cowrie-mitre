# ============================================================
# Security Groups - Honeypot exception, documented and bounded
#
# THE ONE INTENTIONAL EXCEPTION: ports 22 and 2222 are open to
# 0.0.0.0/0. That is the entire point of a honeypot - Cowrie (a
# FAKE shell, not the real OS) listens there and logs attackers.
#
# Everything else stays least-privilege:
#  - Real host admin SSH lives on var.admin_ssh_port, /32 only,
#    or is disabled entirely when SSM is enabled.
#  - Egress from the honeypot is deliberately narrow (DNS, NTP,
#    HTTPS to AWS APIs + the n8n webhook host). A compromised
#    fake-shell must not become a launchpad (no general egress
#    in a production hardening pass: pin webhook CIDR and use
#    VPC endpoints - see README Safety section).
# ============================================================

resource "aws_security_group" "honeypot" {
  name        = "${var.project_name}-sg"
  description = "Cowrie honeypot: 22/2222 world-open by design, admin restricted, narrow egress"
  vpc_id      = data.aws_vpc.default.id

  # --- INTENTIONAL: fake SSH (Cowrie) ---
  ingress {
    description = "Cowrie honeypot SSH - INTENTIONALLY world-open, fake shell only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "Cowrie direct listener 2222 - INTENTIONALLY world-open"
    from_port   = 2222
    to_port     = 2222
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # --- Real host admin: /32 only, and only if SSM is disabled ---
  dynamic "ingress" {
    for_each = var.enable_ssm ? [] : [1]
    content {
      description = "Real host SSH (admin) - operator IP only"
      from_port   = var.admin_ssh_port
      to_port     = var.admin_ssh_port
      protocol    = "tcp"
      cidr_blocks = [var.allowed_admin_cidr]
    }
  }

  # --- Egress: narrow. The honeypot should not talk to the internet at large. ---
  egress {
    description = "HTTPS - package updates, AWS APIs, n8n webhook"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    description = "DNS UDP"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    description = "DNS TCP"
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    description = "NTP"
    from_port   = 123
    to_port     = 123
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project_name}-sg" }
}

# ============================================================
# Network ACL + Blocklist (the CORRECT blocking mechanism)
#
# Security Groups CANNOT deny traffic - they are allow-only and
# stateful. Blocking an attacker IP is therefore done with:
#   1) a Network ACL DENY rule (stateless, explicit deny, this file)
#   2) and/or an AWS WAF IP set when the honeypot fronts an ALB/API
# The block_ip Lambda manages BOTH (see lambda/block_ip.py).
# ============================================================

resource "aws_network_acl" "honeypot" {
  vpc_id     = data.aws_vpc.default.id
  subnet_ids = [local.subnet_id]

  # Baseline inbound allows (specific deny rules inserted by Lambda
  # use rule numbers 10..99, which evaluate BEFORE these allows at 100+)
  ingress {
    rule_no    = 100
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 22
    to_port    = 2222
  }
  ingress {
    rule_no    = 110
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 65535 # return traffic for outbound calls (NACLs are stateless)
  }

  egress {
    rule_no    = 100
    protocol   = "-1"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = { Name = "${var.project_name}-nacl" }
}

# WAF IP set used by the Lambda as a second blocking layer (attach to
# an ALB / API Gateway / CloudFront if you front the honeypot with one).
resource "aws_wafv2_ip_set" "blocklist" {
  name               = "${var.project_name}-blocklist"
  description        = "Attacker IPs confirmed via honeypot + VirusTotal + LLM gate"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = []

  tags = { Name = "${var.project_name}-blocklist" }
}
