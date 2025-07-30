# Outbound endpoint using the rhythmictech/terraform-aws-route53-endpoint module
module "simple-r53-outboud" {
  source            = "git::https://github.com/rhythmictech/terraform-aws-route53-endpoint?ref=v0.3.1"
  direction         = "outbound"
  allowed_resolvers = ["192.168.0.0/24"]
  vpc_id            = "vpc-0fffff0123456789"
  ip_addresses      = [{ subnet_id = "subnet-abcd123456789aaaa" }, { subnet_id = "subnet-abcd123456789bbbb" }]
}

# AWS Route 53 Resolver rules
module "simple-r53-resolver-rules" {
  source               = "git::https://github.com/lgallard/terraform-aws-route53-resolver-rules.git?ref=0.2.0"
  resolver_endpoint_id = module.simple-r53-outboud.endpoint_id

  rules = [
    {
      domain_name = "bar.foo."
      vpc_ids     = ["vpc-0fffff0123456789"]
      ips         = ["192.168.10.10", "192.168.10.11"]
      principals  = ["123456789101", "101987654321"]
    },
    {
      domain_name = "example.com."
      vpc_ids     = ["vpc-0fffff0123456789"]
      ips         = ["192.168.10.10", "192.168.10.11"]
      principals  = ["123456789101", "101987654321"]
    }
  ]

}
