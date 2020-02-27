# Rules
resource "aws_route53_resolver_rule" "r" {
  count = length(var.rules)

  rule_type            = "FORWARD"
  resolver_endpoint_id = var.resolver_endpoint_id

  domain_name = lookup(element(var.rules, count.index), "domain_name", null)
  name        = lookup(element(var.rules, count.index), "rule_name", null)

  dynamic "target_ip" {
    for_each = lookup(element(var.rules, count.index), "ips", [])
    content {
      ip   = split(":", target_ip.value)[0]
      port = length( split(":", target_ip.value)) == 1 ? 53 : split(":", target_ip.value)[1]
    }
  }

  tags = var.tags
}

# Rules associations
resource "aws_route53_resolver_rule_association" "ra" {
  count = length(local.vpcs_associations)
  resolver_rule_id = element(aws_route53_resolver_rule.r.*.id,
    index(aws_route53_resolver_rule.r.*.domain_name, lookup(element(local.vpcs_associations, count.index), "domain_name")
  ))
  vpc_id = lookup(element(local.vpcs_associations, count.index), "vpc_id")

  depends_on = [aws_route53_resolver_rule.r]
}


# RAM association
resource "aws_ram_resource_share" "endpoint_share" {
  count                     = length(local.ram_associations)
  name                      = "r53-${lookup(element(local.ram_associations, count.index), "domain_name")}-${count.index}"
  allow_external_principals = false
}

resource "aws_ram_principal_association" "endpoint_ram_principal" {
  count              = length(local.ram_associations)
  principal          = lookup(element(local.ram_associations, count.index), "principal_id")
  resource_share_arn = aws_ram_resource_share.endpoint_share[count.index].arn
}

resource "aws_ram_resource_association" "endpoint_ram_resource" {
  count = length(local.ram_associations)
  resource_arn = element(aws_route53_resolver_rule.r.*.arn,
    index(aws_route53_resolver_rule.r.*.domain_name, lookup(element(local.ram_associations, count.index), "domain_name")
  ))
  resource_share_arn = aws_ram_resource_share.endpoint_share[count.index].arn
  depends_on         = [aws_route53_resolver_rule.r]
}

locals {
  # vpcs_associations
  vpcs_associations = flatten([
    for rule in var.rules : [
      for vpc in lookup(rule, "vpc_ids") : {
        vpc_id      = vpc
        domain_name = lookup(rule, "domain_name")
      }
    ]
  ])

  # ram_associations
  ram_associations = flatten([
    for rule in var.rules : [
      for principal in lookup(rule, "principals") : {
        principal_id = principal
        domain_name  = lookup(rule, "domain_name")
      }
    ]
  ])
}
