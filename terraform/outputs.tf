output "instance_id" {
  value = aws_instance.honeypot.id
}

output "honeypot_public_ip" {
  description = "Share this only with caution in a lab context - it IS the honeypot"
  value       = aws_instance.honeypot.public_ip
}

output "security_group_id" {
  value = aws_security_group.honeypot.id
}

output "network_acl_id" {
  description = "Pass to block Lambda env NACL_ID (already wired in iam.tf Lambda)"
  value       = aws_network_acl.honeypot.id
}

output "waf_ipset_id" {
  value = aws_wafv2_ip_set.blocklist.id
}

output "block_lambda_arn" {
  description = "Pass to n8n env BLOCK_LAMBDA_ARN"
  value       = aws_lambda_function.block_ip.arn
}

output "admin_hint" {
  value = var.enable_ssm ? "Admin via: aws ssm start-session --target ${aws_instance.honeypot.id} --region ${var.aws_region} (no real SSH port exposed)" : "Admin via: ssh -p ${var.admin_ssh_port} -i <key.pem> ubuntu@${aws_instance.honeypot.public_ip} (your /32 only). Attackers hitting 22 reach Cowrie, not this."
}
