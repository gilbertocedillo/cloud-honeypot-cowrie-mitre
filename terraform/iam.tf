# ============================================================
# IAM - Least Privilege, split by trust level
#
# 1) Honeypot EC2 role: ALMOST NOTHING. The instance is expected
#    to be attacked, so its credentials must be near-worthless:
#    write-only to its own CloudWatch Log Group (+ SSM if enabled).
#    It explicitly CANNOT modify SGs, NACLs, WAF, or other EC2s.
#
# 2) Block Lambda role (separate, never on the honeypot): the ONLY
#    principal allowed to insert NACL deny rules / update the WAF
#    IP set. n8n invokes this Lambda; the honeypot never can.
# ============================================================

data "aws_caller_identity" "current" {}

# ---------------- Honeypot EC2 role ----------------
resource "aws_iam_role" "honeypot" {
  name = "${var.project_name}-ec2-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy" "honeypot_least_privilege" {
  name        = "${var.project_name}-ec2-least-privilege"
  description = "Honeypot EC2: write its own logs only"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "OwnLogGroupOnly"
      Effect = "Allow"
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogStreams"
      ]
      Resource = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/${var.project_name}/*:*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "honeypot_custom" {
  role       = aws_iam_role.honeypot.name
  policy_arn = aws_iam_policy.honeypot_least_privilege.arn
}

resource "aws_iam_role_policy_attachment" "honeypot_ssm" {
  count      = var.enable_ssm ? 1 : 0
  role       = aws_iam_role.honeypot.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "honeypot" {
  name = "${var.project_name}-ec2-profile"
  role = aws_iam_role.honeypot.name
}

resource "aws_cloudwatch_log_group" "honeypot" {
  name              = "/${var.project_name}/cowrie"
  retention_in_days = 30
}

# ---------------- Block Lambda role ----------------
resource "aws_iam_role" "block_lambda" {
  name = "${var.project_name}-block-lambda-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy" "block_lambda" {
  name        = "${var.project_name}-block-lambda"
  description = "Only: insert/delete NACL entries on this project's NACL, update this WAF IP set, own logs"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "NaclDenyOnProjectNacl"
        Effect   = "Allow"
        Action   = ["ec2:CreateNetworkAclEntry", "ec2:DeleteNetworkAclEntry", "ec2:DescribeNetworkAcls"]
        Resource = aws_network_acl.honeypot.arn
      },
      {
        Sid      = "WafBlocklistOnly"
        Effect   = "Allow"
        Action   = ["wafv2:GetIPSet", "wafv2:UpdateIPSet"]
        Resource = aws_wafv2_ip_set.blocklist.arn
      },
      {
        Sid    = "OwnLogs"
        Effect = "Allow"
        Action = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.project_name}-block-ip:*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "block_lambda" {
  role       = aws_iam_role.block_lambda.name
  policy_arn = aws_iam_policy.block_lambda.arn
}

resource "aws_lambda_function" "block_ip" {
  function_name = "${var.project_name}-block-ip"
  role          = aws_iam_role.block_lambda.arn
  handler       = "block_ip.handler"
  runtime       = "python3.12"
  timeout       = 30
  # Deploy code from ../../lambda - zip it first:
  #   cd ../../lambda && zip block_ip.zip block_ip.py
  filename         = "${path.module}/../../lambda/block_ip.zip"
  source_code_hash = fileexists("${path.module}/../../lambda/block_ip.zip") ? filebase64sha256("${path.module}/../../lambda/block_ip.zip") : null

  environment {
    variables = {
      NACL_ID          = aws_network_acl.honeypot.id
      WAF_IPSET_ID     = aws_wafv2_ip_set.blocklist.id
      WAF_IPSET_NAME   = aws_wafv2_ip_set.blocklist.name
      DRY_RUN          = "true" # flip to "false" only after testing the full pipeline
      MAX_BLOCKED_IPS  = "900"
    }
  }

  tags = { Name = "${var.project_name}-block-ip" }
}
