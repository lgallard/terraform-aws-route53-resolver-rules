config {
  call_module_type = "all"
  force = false
  disabled_by_default = false
}

plugin "aws" {
  enabled = true
  version = "0.32.0"
  source  = "github.com/terraform-linters/tflint-ruleset-aws"
}

# General Terraform rules
rule "terraform_deprecated_interpolation" {
  enabled = true
}

rule "terraform_deprecated_index" {
  enabled = true
}

rule "terraform_unused_declarations" {
  enabled = true
}

rule "terraform_comment_syntax" {
  enabled = true
}

rule "terraform_documented_outputs" {
  enabled = true
}

rule "terraform_documented_variables" {
  enabled = true
}

rule "terraform_typed_variables" {
  enabled = true
}

rule "terraform_module_pinned_source" {
  enabled = true
}

rule "terraform_naming_convention" {
  enabled = true
  format  = "snake_case"
}

rule "terraform_required_version" {
  enabled = true
}

rule "terraform_required_providers" {
  enabled = true
}

rule "terraform_standard_module_structure" {
  enabled = true
}

# AWS-specific rules for Route53 and networking
rule "aws_route53_resolver_endpoint_invalid_ip_address" {
  enabled = true
}

rule "aws_route53_resolver_rule_invalid_domain_name" {
  enabled = true
}

rule "aws_instance_invalid_type" {
  enabled = true
}

rule "aws_s3_bucket_invalid_region" {
  enabled = true
}

# Network security rules
rule "aws_security_group_rule_invalid_protocol" {
  enabled = true
}

rule "aws_db_instance_invalid_type" {
  enabled = true
}

# Resource naming and tagging
rule "aws_resource_missing_tags" {
  enabled = false  # Disabled as tags are optional in many cases
  tags = ["Environment", "Project"]
}