![Terraform](https://lgallardo.com/images/terraform.jpg)
# terraform-aws-route53-resolver-rules

Terraform module to create [AWS Route53 Resolver Rules](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver.html/).

## Usage

Before you start to forward queries, you must create  Resolver outbound endpoints in the connected VPCs. These endpoints provide a path for inbound or outbound queries. To accomplish this you can create the endpoints using the [aws_route53_resolver_endpoint](https://www.terraform.io/docs/providers/aws/r/route53_resolver_endpoint.html) resource or use a module like the [terraform-aws-route53-endpoint](https://github.com/rhythmictech/terraform-aws-route53-endpoint)

Check the [examples](examples/) folder for the **simple** and the **complete** snippets.

### Example (complete)

This example creates two rules in a outbound endpoint, using all the parameter expected for building the rules:

```
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

```

**Note**: You can define IP and ports using the *IP:PORT* syntax, as shown above.

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| resolver\_endpoint\_id | The ID of the outbound resolver endpoint that you want to use to route DNS queries to the IP addresses that you specify using target\_ip. | `string` | `null` | yes |
| rules | List of rules | `list` | `[]` | no |
| tags | Map of tags to apply to supported resources | `map(string)` | `{}` | no |

Each rule accept the following parameters:

### Rules

| Name | Description | Type | Default | Required |
|------|-------------|:----:|:-----:|:-----:|
| domain\_name | Domain name to forward requests for | string | `null` | yes |
| ips | List of IPs and ports to forward DNS requests to. Use *IP:PORT* syntax, or just the IP | list(string) | `[]`| yes |
| principals | List of account IDs to share the resolver rule with | list(string) | `[]` | no |
| ram\_name | RAM share name | string | r53-`domain_name`-rule | no |
| resolver\_endpoint\_id | Resolver endpoint id | string | `null` | yes |
| rule\_name | Route53 resolver rule name | string | `domain_name`-rule | no |
| tags | Map of tags to apply to supported resources | map(string) | `{}` | no |
| vpc\_ids | List of VPC ids to associate to the rule | list(string) | `[]` | yes |
