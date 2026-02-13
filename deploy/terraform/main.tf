# Qbitel EdgeOS - Terraform Infrastructure Configuration
# Provisions fleet management, OTA update, and monitoring infrastructure

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    bucket         = "q-edge-os-terraform-state"
    key            = "infrastructure/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "q-edge-os-terraform-locks"
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "Qbitel-EdgeOS"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

# Variables
variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "fleet_name" {
  description = "Name of the device fleet"
  type        = string
  default     = "q-edge-fleet"
}

# S3 bucket for firmware updates
resource "aws_s3_bucket" "firmware_updates" {
  bucket = "q-edge-os-firmware-${var.environment}"
}

resource "aws_s3_bucket_versioning" "firmware_updates" {
  bucket = aws_s3_bucket.firmware_updates.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "firmware_updates" {
  bucket = aws_s3_bucket.firmware_updates.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "firmware_updates" {
  bucket = aws_s3_bucket.firmware_updates.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# S3 bucket for device telemetry
resource "aws_s3_bucket" "telemetry" {
  bucket = "q-edge-os-telemetry-${var.environment}"
}

resource "aws_s3_bucket_lifecycle_configuration" "telemetry" {
  bucket = aws_s3_bucket.telemetry.id

  rule {
    id     = "archive-old-telemetry"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }
  }
}

# DynamoDB table for device registry
resource "aws_dynamodb_table" "device_registry" {
  name           = "q-edge-device-registry-${var.environment}"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "device_id"

  attribute {
    name = "device_id"
    type = "S"
  }

  attribute {
    name = "fleet_id"
    type = "S"
  }

  attribute {
    name = "device_class"
    type = "S"
  }

  global_secondary_index {
    name            = "fleet-index"
    hash_key        = "fleet_id"
    projection_type = "ALL"
  }

  global_secondary_index {
    name            = "device-class-index"
    hash_key        = "device_class"
    projection_type = "ALL"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled = true
  }

  tags = {
    Name = "Qbitel EdgeOS Device Registry"
  }
}

# DynamoDB table for attestation records
resource "aws_dynamodb_table" "attestation_records" {
  name           = "q-edge-attestation-${var.environment}"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "device_id"
  range_key      = "timestamp"

  attribute {
    name = "device_id"
    type = "S"
  }

  attribute {
    name = "timestamp"
    type = "N"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = {
    Name = "Qbitel EdgeOS Attestation Records"
  }
}

# IoT Core for device connectivity
resource "aws_iot_thing_group" "fleet" {
  name = var.fleet_name

  properties {
    description = "Qbitel EdgeOS device fleet"
  }
}

resource "aws_iot_policy" "device_policy" {
  name = "q-edge-device-policy-${var.environment}"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["iot:Connect"]
        Resource = "arn:aws:iot:${var.aws_region}:*:client/$${iot:Connection.Thing.ThingName}"
      },
      {
        Effect = "Allow"
        Action = [
          "iot:Publish",
          "iot:Receive"
        ]
        Resource = [
          "arn:aws:iot:${var.aws_region}:*:topic/q-edge/$${iot:Connection.Thing.ThingName}/*",
          "arn:aws:iot:${var.aws_region}:*:topic/q-edge/fleet/${var.fleet_name}/*"
        ]
      },
      {
        Effect   = "Allow"
        Action   = ["iot:Subscribe"]
        Resource = "arn:aws:iot:${var.aws_region}:*:topicfilter/q-edge/$${iot:Connection.Thing.ThingName}/*"
      }
    ]
  })
}

# Lambda for OTA update orchestration
resource "aws_lambda_function" "ota_orchestrator" {
  function_name = "q-edge-ota-orchestrator-${var.environment}"
  runtime       = "python3.11"
  handler       = "handler.lambda_handler"
  role          = aws_iam_role.lambda_ota.arn
  timeout       = 300
  memory_size   = 512

  filename         = "${path.module}/lambda/ota_orchestrator.zip"
  source_code_hash = filebase64sha256("${path.module}/lambda/ota_orchestrator.zip")

  environment {
    variables = {
      FIRMWARE_BUCKET = aws_s3_bucket.firmware_updates.id
      DEVICE_TABLE    = aws_dynamodb_table.device_registry.name
      ENVIRONMENT     = var.environment
    }
  }

  tracing_config {
    mode = "Active"
  }
}

resource "aws_iam_role" "lambda_ota" {
  name = "q-edge-lambda-ota-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda_ota.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Least-privilege policy for OTA orchestrator Lambda
resource "aws_iam_role_policy" "lambda_ota_access" {
  name = "q-edge-lambda-ota-access-${var.environment}"
  role = aws_iam_role.lambda_ota.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3FirmwareReadAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.firmware_updates.arn,
          "${aws_s3_bucket.firmware_updates.arn}/*"
        ]
      },
      {
        Sid    = "DynamoDBDeviceRegistryAccess"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:Query",
          "dynamodb:Scan"
        ]
        Resource = [
          aws_dynamodb_table.device_registry.arn,
          "${aws_dynamodb_table.device_registry.arn}/index/*"
        ]
      },
      {
        Sid    = "XRayTracingAccess"
        Effect = "Allow"
        Action = [
          "xray:PutTraceSegments",
          "xray:PutTelemetryRecords"
        ]
        Resource = ["*"]
      }
    ]
  })
}

# CloudWatch dashboard for fleet monitoring
resource "aws_cloudwatch_dashboard" "fleet_dashboard" {
  dashboard_name = "Qbitel-EdgeOS-Fleet-${var.environment}"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "Active Devices"
          region = var.aws_region
          metrics = [
            ["QbitelEdgeOS", "ActiveDevices", "Fleet", var.fleet_name]
          ]
          period = 300
          stat   = "Average"
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "OTA Update Success Rate"
          region = var.aws_region
          metrics = [
            ["QbitelEdgeOS", "OTASuccess", "Fleet", var.fleet_name],
            ["QbitelEdgeOS", "OTAFailure", "Fleet", var.fleet_name]
          ]
          period = 300
          stat   = "Sum"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 24
        height = 6
        properties = {
          title  = "Attestation Events"
          region = var.aws_region
          metrics = [
            ["QbitelEdgeOS", "AttestationSuccess", "Fleet", var.fleet_name],
            ["QbitelEdgeOS", "AttestationFailure", "Fleet", var.fleet_name]
          ]
          period = 60
          stat   = "Sum"
        }
      }
    ]
  })
}

# Outputs
output "firmware_bucket" {
  description = "S3 bucket for firmware updates"
  value       = aws_s3_bucket.firmware_updates.id
}

output "device_registry_table" {
  description = "DynamoDB table for device registry"
  value       = aws_dynamodb_table.device_registry.name
}

output "iot_policy_name" {
  description = "IoT policy name for devices"
  value       = aws_iot_policy.device_policy.name
}

output "fleet_thing_group" {
  description = "IoT Thing Group ARN"
  value       = aws_iot_thing_group.fleet.arn
}
