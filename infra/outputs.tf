output "raw_bucket_name" {
  value = aws_s3_bucket.raw_logs.bucket
}

output "redacted_table_name" {
  value = aws_dynamodb_table.redacted_logs.name
}

output "mapping_table_name" {
  value = aws_dynamodb_table.pii_mappings.name
}

output "audit_table_name" {
  value = aws_dynamodb_table.audit_log.name
}
