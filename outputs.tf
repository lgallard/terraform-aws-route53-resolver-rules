output "rr_ids" {
  description = "Resolver rule IDs"
  value       = try(aws_route53_resolver_rule.r.id, null)
}
