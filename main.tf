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
      ip   = split(":", target_ip.value)[0]
      port = length(split(":", target_ip.value)) == 1 ? 53 : (
        can(tonumber(split(":", target_ip.value)[1])) ? 
        tonumber(split(":", target_ip.value)[1]) : 
        53  # Default to port 53 if conversion fails
      )
    }
  }

  tags = var.tags
}

# Rules associations
resource "aws_route53_resolver_rule_association" "ra" {
  for_each = local.vpcs_associations
  
  resolver_rule_id = aws_route53_resolver_rule.r[each.value.domain_name].id
  vpc_id          = each.value.vpc_id

  depends_on = [aws_route53_resolver_rule.r]
}

# RAM association
# One per rule
resource "aws_ram_resource_share" "endpoint_share" {
  for_each = local.ram_shares
  
  name                      = each.value.ram_name
  allow_external_principals = false
}

# Add principals to the above resource share
resource "aws_ram_principal_association" "endpoint_ram_principal" {
  for_each = local.ram_associations
  
  principal = each.value.principal_id
  resource_share_arn = aws_ram_resource_share.endpoint_share[each.value.ram_name].arn

  depends_on = [aws_ram_resource_share.endpoint_share]
}

resource "aws_ram_resource_association" "endpoint_ram_resource" {
  for_each = local.ram_shares
  
  resource_arn       = aws_route53_resolver_rule.r[each.value.domain_name].arn
  resource_share_arn = aws_ram_resource_share.endpoint_share[each.key].arn
  
  depends_on = [aws_route53_resolver_rule.r]
}

locals {
  # Process rules with defaults - optimized with direct attribute access
  rules = {
    for rule in var.rules : rule.domain_name => {
      rule_name   = coalesce(rule.rule_name, "${rule.domain_name}-rule")
      domain_name = rule.domain_name
      ram_name    = coalesce(rule.ram_name, "r53-${rule.domain_name}")
      vpc_ids     = rule.vpc_ids
      ips         = rule.ips
      principals  = coalesce(rule.principals, [])
    }
  }

  # Optimized single-pass flattening for VPC associations
  vpcs_associations = {
    for pair in flatten([
      for rule in var.rules : [
        for vpc in rule.vpc_ids : {
          key         = "${rule.domain_name}-${vpc}"
          vpc_id      = vpc
          domain_name = rule.domain_name
        }
      ]
    ]) : pair.key => pair
  }

  # RAM shares - one per unique ram_name
  ram_shares = {
    for rule in var.rules : coalesce(rule.ram_name, "r53-${rule.domain_name}") => {
      ram_name    = coalesce(rule.ram_name, "r53-${rule.domain_name}")
      domain_name = rule.domain_name
    }
    if length(coalesce(rule.principals, [])) > 0
  }

  # RAM associations - flattened for each principal
  ram_associations = {
    for pair in flatten([
      for rule in var.rules : [
        for principal in coalesce(rule.principals, []) : {
          key          = "${coalesce(rule.ram_name, "r53-${rule.domain_name}")}-${principal}"
          principal_id = principal
          ram_name     = coalesce(rule.ram_name, "r53-${rule.domain_name}")
        }
      ] if length(coalesce(rule.principals, [])) > 0
    ]) : pair.key => pair
  }
}
