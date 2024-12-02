output "resolver_rules" {
  description = "Resolver rules"
  value = {
    for rule in aws_route53_resolver_rule.r : rule.domain_name => {
      name                  = rule.name
      rule_type             = rule.rule_type
      resolver_rule_id      = rule.id
      resolver_endpoint_id  = rule.resolver_endpoint_id
    }
  }
}
