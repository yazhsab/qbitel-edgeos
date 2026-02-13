# Qbitel EdgeOS - Terraform Variables

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "qbitel-edgeos"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "enable_hsm" {
  description = "Enable CloudHSM for key management"
  type        = bool
  default     = false
}

variable "enable_waf" {
  description = "Enable WAF for API protection"
  type        = bool
  default     = true
}

variable "retention_days" {
  description = "Log retention period in days"
  type        = number
  default     = 90
}

variable "alarm_email" {
  description = "Email for CloudWatch alarms"
  type        = string
  default     = ""
}

variable "max_devices" {
  description = "Maximum number of devices in fleet"
  type        = number
  default     = 10000
}

variable "firmware_signing_key_arn" {
  description = "ARN of the KMS key for firmware signing"
  type        = string
  default     = ""
}
