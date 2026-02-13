# Qbitel EdgeOS - Terraform Outputs

output "environment" {
  description = "Deployment environment"
  value       = var.environment
}

output "region" {
  description = "AWS region"
  value       = var.aws_region
}

output "telemetry_bucket" {
  description = "S3 bucket for telemetry data"
  value       = aws_s3_bucket.telemetry.id
}

output "attestation_table" {
  description = "DynamoDB table for attestation records"
  value       = aws_dynamodb_table.attestation_records.name
}

output "ota_lambda_arn" {
  description = "ARN of the OTA orchestrator Lambda"
  value       = aws_lambda_function.ota_orchestrator.arn
}

output "dashboard_url" {
  description = "CloudWatch dashboard URL"
  value       = "https://${var.aws_region}.console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:name=${aws_cloudwatch_dashboard.fleet_dashboard.dashboard_name}"
}
