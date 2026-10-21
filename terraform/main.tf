terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# --- Latest Ubuntu 24.04 LTS AMI (Cowrie upstream targets Debian/Ubuntu) ---
data "aws_ssm_parameter" "ubuntu" {
  name = "/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id"
}

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

locals {
  subnet_id = data.aws_subnets.default.ids[0]
}

# --- Honeypot EC2 ---
# ISOLATION POSTURE: this instance is intentionally exposed on 22/2222.
# It holds NO real data, NO credentials for other systems, and its IAM role
# can do almost nothing (see iam.tf). Treat every byte on it as hostile.
resource "aws_instance" "honeypot" {
  ami                    = data.aws_ssm_parameter.ubuntu.value
  instance_type          = var.instance_type
  subnet_id              = local.subnet_id
  vpc_security_group_ids = [aws_security_group.honeypot.id]
  iam_instance_profile   = aws_iam_instance_profile.honeypot.name
  key_name               = var.key_pair_name != "" ? var.key_pair_name : null

  # IMDSv2 ONLY - a honeypot WILL be probed; do not let SSRF steal creds
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    encrypted             = true
    volume_type           = "gp3"
    volume_size           = 20
    delete_on_termination = true
  }

  user_data = templatefile("${path.module}/user_data.sh.tpl", {
    webhook_url   = var.webhook_url
    project       = var.project_name
    region        = var.aws_region
    admin_ssh_port = var.admin_ssh_port
  })

  tags = {
    Name        = "${var.project_name}-cowrie-ec2"
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "Terraform"
    Role        = "honeypot"
  }
}
