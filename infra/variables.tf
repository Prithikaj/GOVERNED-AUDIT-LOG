variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "ap-south-1"
}

variable "raw_bucket" {
  description = "S3 bucket name for raw logs"
  type        = string
  default     = "ps72-raw-logs"
}

variable "redacted_table" {
  description = "DynamoDB table name for redacted records"
  type        = string
  default     = "ps72-redacted-logs"
}

variable "mapping_table" {
  description = "DynamoDB table name for token mappings"
  type        = string
  default     = "ps72-pii-mapping"
}

variable "audit_table" {
  description = "DynamoDB table name for access audit entries"
  type        = string
  default     = "ps72-access-audit"
}
