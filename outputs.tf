output "rr_ids" {
  description = "Resolver rule IDs"
  value       = try(aws_route53_resolver_rule.r.*.id, [])
}

output "resolver_rules" {
  value = {
    for rule in aws_route53_resolver_rule.r : rule.domain_name => {
      name = rule.name
      type = rule.rule_type
      ttl  = rule.resolver_endpoint_id
    }
  }
}
