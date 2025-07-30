# Rules
resource "aws_route53_resolver_rule" "r" {
  for_each = local.rules

  rule_type            = "FORWARD"
  resolver_endpoint_id = var.resolver_endpoint_id

  domain_name = each.value.domain_name
  name        = each.value.rule_name

  dynamic "target_ip" {
    for_each = each.value.ips
    content {
      ip   = local.ip_port_split[target_ip.value].ip
      port = local.ip_port_split[target_ip.value].port
    }
  }

  tags = var.tags
}

# Rules associations
resource "aws_route53_resolver_rule_association" "ra" {
  for_each = local.vpcs_associations

  resolver_rule_id = aws_route53_resolver_rule.r[each.value.domain_name].id
  vpc_id           = each.value.vpc_id

  depends_on = [aws_route53_resolver_rule.r]
}

# RAM association
# One per rule that has principals
resource "aws_ram_resource_share" "endpoint_share" {
  for_each = local.resource_shares

  name                      = each.key
  allow_external_principals = false
}

# Add principals to the above resource share
resource "aws_ram_principal_association" "endpoint_ram_principal" {
  for_each = local.ram_associations

  principal          = each.value.principal_id
  resource_share_arn = aws_ram_resource_share.endpoint_share[each.value.ram_name].arn

  depends_on = [aws_ram_resource_share.endpoint_share]
}

resource "aws_ram_resource_association" "endpoint_ram_resource" {
  for_each = local.resource_shares

  resource_arn       = aws_route53_resolver_rule.r[each.value].arn
  resource_share_arn = aws_ram_resource_share.endpoint_share[each.key].arn
  depends_on         = [aws_route53_resolver_rule.r]
}

locals {
  # Step 1: Split IP strings once to avoid race conditions
  ip_parts_map = {
    for ip_value in flatten([for rule in var.rules : lookup(rule, "ips", [])]) : ip_value => split(":", ip_value)
  }

  # Step 2: Parse IP and port from pre-split parts
  ip_port_split = {
    for ip_value, ip_parts in local.ip_parts_map : ip_value => {
      ip   = ip_parts[0]
      port = length(ip_parts) > 1 && can(tonumber(ip_parts[1])) && tonumber(ip_parts[1]) > 0 && tonumber(ip_parts[1]) <= 65535 ? tonumber(ip_parts[1]) : 53
    }
  }

  # Process rules with defaults - optimized with direct attribute access
  rules = {
    for rule in var.rules : lookup(rule, "domain_name") => {
      rule_name   = lookup(rule, "rule_name", "${lookup(rule, "domain_name")}-rule")
      domain_name = lookup(rule, "domain_name", null)
      ram_name    = lookup(rule, "ram_name", "r53-${lookup(rule, "domain_name")}")
      vpc_ids     = lookup(rule, "vpc_ids", [])
      ips         = lookup(rule, "ips", [])
      principals  = lookup(rule, "principals", [])
    }
  }

  # Optimized single-pass flattening for VPC associations
  vpcs_associations = {
    for pair in flatten([
      for rule in var.rules : [
        for vpc in lookup(rule, "vpc_ids", []) : {
          key         = "${lookup(rule, "domain_name")}-${vpc}"
          vpc_id      = vpc
          domain_name = lookup(rule, "domain_name")
        }
      ]
    ]) : pair.key => pair
  }

  # RAM associations flattening
  ram_associations = {
    for pair in flatten([
      for rule in var.rules : [
        for principal in lookup(rule, "principals", []) : {
          key          = "${lookup(rule, "domain_name")}-${principal}"
          principal_id = principal
          ram_name     = lookup(rule, "ram_name", lookup(rule, "domain_name"))
        }
      ] if length(lookup(rule, "principals", [])) > 0
    ]) : pair.key => pair
  }

  # Create resource shares map for efficient lookups
  resource_shares = {
    for rule in var.rules : lookup(rule, "ram_name", lookup(rule, "domain_name")) => lookup(rule, "domain_name")
    if length(lookup(rule, "principals", [])) > 0
  }
}

# Terraform moved blocks for state migration from count to for_each
# These blocks enable seamless migration from v0.3.x to v0.4.x

# Map resolver rules from count[N] to domain_name key
# Note: Dynamic expressions are not allowed in moved blocks
# Users migrating from v0.3.x should use the migration script instead
# moved {
#   from = aws_route53_resolver_rule.r[0]
#   to   = aws_route53_resolver_rule.r["example.com."]
# }

# Dynamic moved blocks would be ideal but are not supported yet
# Users with multiple rules will need to use the migration script or manual state moves
