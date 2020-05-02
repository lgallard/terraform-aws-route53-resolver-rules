# Outbound endpoint using the rhythmictech/terraform-aws-route53-endpoint module
module "r53-outboud" {
  source            = "git::https://github.com/rhythmictech/terraform-aws-route53-endpoint"
  direction         = "outbound"
  allowed_resolvers = ["192.168.0.0/24"]
  vpc_id            = "vpc-0fffff0123456789"
  ip_addresses      = [
    {
      ip        = "172.30.1.10"
      subnet_id = "subnet-abcd123456789aaaa"
    },
    {
      ip        = "172.30.2.10"
      subnet_id = "subnet-abcd123456789bbbb"
    }
  ]
}

# AWS Route 53 Resolver rules
module "r53-resolver-rules" {
  source               = "git::https://github.com/lgallard/terraform-aws-route53-resolver-rules.git"
  resolver_endpoint_id = module.r53-outboud.endpoint_ids

  rules = [
    { rule_name   = "r53r-rule-1"
      domain_name = "bar.foo."
      ram_name    = "ram-r53r-1"
      vpc_ids     = ["vpc-0fffff0123456789"]
      ips         = ["192.168.10.10", "192.168.10.11:54"]
      principals  = ["123456789101", "101987654321"]
    },
    {
      rule_name   = "r53r-rule-2"
      domain_name = "example.com."
      ram_name    = "ram-r53r-2"
      vpc_ids     = ["vpc-0fffff0123456789"]
      ips         = ["192.168.10.10", "192.168.10.11:54"]
      principals  = ["123456789101", "101987654321"]
    }
  ]

}