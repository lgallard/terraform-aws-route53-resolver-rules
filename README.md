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
module "r53-outbound" {
  source            = "git::https://github.com/rhythmictech/terraform-aws-route53-endpoint?ref=v0.3.1"
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
  source               = "git::https://github.com/lgallard/terraform-aws-route53-resolver-rules.git?ref=0.2.0"
  resolver_endpoint_id = module.r53-outbound.endpoint_id

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

## Testing

This module includes comprehensive tests using [Terratest](https://github.com/gruntwork-io/terratest). The test suite covers:

- Basic resolver rule creation and validation
- Multiple resolver rules with different configurations
- VPC association functionality
- RAM resource sharing for cross-account scenarios
- Custom DNS port configurations
- Resource tagging
- Input validation and edge cases

### Running Tests

To run the tests locally:

```bash
cd test
go mod tidy
go test -v -timeout 30m
```

For more details on the testing framework and how to run specific tests, see the [test documentation](test/README.md).

### Test Coverage

- ✅ Basic resolver rule creation
- ✅ Multiple resolver rules
- ✅ VPC associations
- ✅ RAM resource sharing
- ✅ Custom DNS ports
- ✅ Resource tagging
- ✅ Input validation and error cases
- ✅ Module outputs
- ✅ Edge cases and boundary conditions

## Development

### Pre-commit Hooks

This repository uses pre-commit hooks to ensure code quality and DNS/networking-specific validation. The hooks include:

- **Terraform formatting** (`terraform fmt`)
- **Terraform validation** (`terraform validate`)
- **Terraform documentation** (auto-generated)
- **TFLint** for advanced Terraform linting
- **TFSec** for security scanning
- **DNS domain validation** (ensures FQDN format with trailing dots)
- **VPC ID format validation**
- **IP address format validation**
- **YAML/JSON validation**
- **Secret detection**
- **File formatting** (trailing whitespace, end-of-file fixes)

#### Setup

1. **Install pre-commit**:
   ```bash
   pip install pre-commit
   ```

2. **Install the hooks**:
   ```bash
   pre-commit install
   ```

3. **Run hooks manually** (optional):
   ```bash
   # Run on all files
   pre-commit run --all-files
   
   # Run on specific files
   pre-commit run --files main.tf variables.tf
   ```

#### DNS-Specific Validations

The pre-commit hooks include custom validations for Route53 resolver rules:

- **Domain Names**: Must be fully qualified (end with a dot), e.g., `"example.com."`
- **VPC IDs**: Must follow AWS format, e.g., `"vpc-12345678"`
- **IP Addresses**: Must use valid IPv4 format, optionally with ports, e.g., `"192.168.1.1:53"`

#### Configuration Files

The pre-commit setup includes several configuration files:

- `.pre-commit-config.yaml` - Main pre-commit configuration
- `.tflint.hcl` - TFLint rules for Terraform linting
- `.tfsec.yml` - TFSec security scanning configuration
- `.terraform-docs.yml` - Terraform documentation generation
- `.secrets.baseline` - Baseline for secret detection

These hooks run automatically on every commit and help maintain code quality, security, and DNS/networking best practices.

<!-- BEGIN_TF_DOCS -->


## Usage

Before you start to forward queries, you must create Resolver outbound endpoints in the connected VPCs. These endpoints provide a path for inbound or outbound queries. To accomplish this you can create the endpoints using the [aws_route53_resolver_endpoint](https://www.terraform.io/docs/providers/aws/r/route53_resolver_endpoint.html) resource or use a module like the [terraform-aws-route53-endpoint](https://github.com/rhythmictech/terraform-aws-route53-endpoint)

Check the [examples](examples/) folder for the **simple** and the **complete** snippets.

### Example (complete)

This example creates two rules in a outbound endpoint, using all the parameter expected for building the rules:

```hcl
# Outbound endpoint using the rhythmictech/terraform-aws-route53-endpoint module
module "r53-outbound" {
  source            = "git::https://github.com/rhythmictech/terraform-aws-route53-endpoint?ref=v0.3.1"
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
  source               = "git::https://github.com/lgallard/terraform-aws-route53-resolver-rules.git?ref=0.2.0"
  resolver_endpoint_id = module.r53-outbound.endpoint_id

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

## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.0 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | >= 4.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | 6.6.0 |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [aws_ram_principal_association.endpoint_ram_principal](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ram_principal_association) | resource |
| [aws_ram_resource_association.endpoint_ram_resource](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ram_resource_association) | resource |
| [aws_ram_resource_share.endpoint_share](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ram_resource_share) | resource |
| [aws_route53_resolver_rule.r](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route53_resolver_rule) | resource |
| [aws_route53_resolver_rule_association.ra](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route53_resolver_rule_association) | resource |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_resolver_endpoint_id"></a> [resolver\_endpoint\_id](#input\_resolver\_endpoint\_id) | The ID of the outbound resolver endpoint that you want to use to route DNS queries to the IP addresses specified in target\_ip | `string` | `null` | no |
| <a name="input_rules"></a> [rules](#input\_rules) | List of rules | `list(any)` | `[]` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | Map of tags to apply to supported resources. Each tag is a key-value pair stored as a map of strings. | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_resolver_rules"></a> [resolver\_rules](#output\_resolver\_rules) | Resolver rules |

<!-- END_TF_DOCS -->