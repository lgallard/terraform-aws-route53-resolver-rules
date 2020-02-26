# AWS Route 53 Resolver rules

```
# AWS Route 53 Resolver rules
module "r53-resolver-rules" {
  source            = "../modules/terraform-aws-route53-resolver-rules"

  resolver_endpoint = module.r53-resolver-outboud.endpoint_id

  rules = [
    { rule_name       = "r53-rule1"
      domain_name     = "example.com."
      vpc_ids         = ["vpc-11111111111111111", "vpc-22222222222222222"]
      ips             = ["190.156.114.123", "190.156.114.125"]
      principals      = ["123456789101", "101987654321", "123455554321"]
    },
    {
      rule_name       = "r53-rule2"
      domain_name     = "bar.foo."
      vpc_ids         = ["vpc-11111111111111111"]
      ips             = ["190.156.114.123", "190.156.114.125"]
      principals      = ["123456789101", "101987654321", "123455554321"]
    }
  ]
}
```
