terraform {
  required_version = ">= 1.5.0"
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

resource "aws_s3_bucket" "raw_logs" {
  bucket = var.raw_bucket
}

resource "aws_dynamodb_table" "redacted_logs" {
  name           = var.redacted_table
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "record_id"
  attribute {
    name = "record_id"
    type = "S"
  }
}

resource "aws_dynamodb_table" "pii_mappings" {
  name           = var.mapping_table
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "record_id"
  attribute {
    name = "record_id"
    type = "S"
  }
}

resource "aws_dynamodb_table" "audit_log" {
  name           = var.audit_table
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "audit_id"
  attribute {
    name = "audit_id"
    type = "S"
  }
}
