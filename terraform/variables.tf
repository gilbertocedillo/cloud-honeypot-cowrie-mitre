variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Prefix for all resources"
  type        = string
  default     = "honeypot-lab"
}

variable "environment" {
  type    = string
  default = "lab"
}

variable "instance_type" {
  description = "EC2 type - t3.micro/small is enough for Cowrie"
  type        = string
  default     = "t3.small"
}

variable "allowed_admin_cidr" {
  description = "YOUR public IP in /32 for real admin SSH (port 22022). NEVER 0.0.0.0/0. Get it: curl ifconfig.me"
  type        = string
  # No default on purpose: forces least-privilege explicit input
}

variable "webhook_url" {
  description = "n8n Webhook URL that will receive honeypot JSON alerts"
  type        = string
  sensitive   = true
}

variable "key_pair_name" {
  description = "Existing EC2 Key Pair for admin SSH on 22022 (optional if SSM is used - recommended)"
  type        = string
  default     = ""
}

variable "enable_ssm" {
  description = "Use SSM Session Manager for admin instead of exposing any real SSH port"
  type        = bool
  default     = true
}

variable "admin_ssh_port" {
  description = "Real sshd port for the host OS (Cowrie owns 22/2222). Keep admin on a non-standard port, /32 only."
  type        = number
  default     = 22022
}
