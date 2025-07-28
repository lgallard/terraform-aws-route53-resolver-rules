# Terraform AWS Route53 Resolver Rules Module - Development Guidelines

## Overview
This document outlines Terraform-specific development guidelines for the terraform-aws-route53-resolver-rules module, focusing on DNS forwarding patterns, networking considerations, and best practices for Route53 Resolver infrastructure as code.

The module manages DNS forwarding rules that route specific domain queries from VPCs to designated DNS servers through Route53 Resolver endpoints, with support for cross-account sharing via AWS RAM (Resource Access Manager).

## Module Structure & Organization

### File Organization
- **main.tf** - Primary resource definitions (resolver rules, associations, RAM resources) and locals
- **variables.tf** - Input variable definitions with validation
- **outputs.tf** - Output value definitions for resolver rules
- **versions.tf** - Provider version constraints

### Code Organization Principles
- Group DNS resolution resources logically
- Use descriptive locals for complex rule processing
- Maintain backward compatibility with existing rule structures
- Keep RAM sharing logic separated but coordinated with rule creation

## Route53 Resolver Patterns

### DNS Forwarding Architecture
The module implements the following DNS forwarding pattern:
```
VPC --> Route53 Resolver Endpoint --> External DNS Servers
```

**Key Components:**
- **Resolver Rules**: Define which domains to forward and to which DNS servers
- **Rule Associations**: Associate rules with specific VPCs
- **RAM Sharing**: Share rules across AWS accounts for centralized DNS management

### Rule Creation Patterns
**Prefer structured rule definitions** for maintainability:

```hcl
# Preferred: Structured rule definition
rules = [
  {
    rule_name   = "corporate-dns-rule"
    domain_name = "internal.company.com."
    ram_name    = "corporate-dns-share"
    vpc_ids     = ["vpc-12345678", "vpc-87654321"]
    ips         = ["10.0.0.10:53", "10.0.0.11:53"]
    principals  = ["123456789012", "210987654321"]
  }
]

# Avoid: Inconsistent or incomplete rule structures
rules = [
  {
    domain_name = "example.com"  # Missing trailing dot
    ips         = ["192.168.1.1"] # Missing port specification
    # Missing required VPC associations
  }
]
```

### DNS Domain Naming Conventions
**Always use fully qualified domain names (FQDN)** with trailing dots:

```hcl
# Correct: FQDN with trailing dot
domain_name = "internal.company.com."

# Incorrect: Missing trailing dot (can cause resolution issues)
domain_name = "internal.company.com"
```

### IP Address and Port Specification
**Support both implicit and explicit port definitions:**

```hcl
# Module handles both formats automatically
ips = [
  "192.168.10.10",      # Defaults to port 53
  "192.168.10.11:5353"  # Explicit port specification
]

# Internal parsing logic splits on colon with proper error handling
ip   = split(":", target_ip.value)[0]
port = length(split(":", target_ip.value)) == 1 ? 53 : (
  can(tonumber(split(":", target_ip.value)[1])) ? 
  tonumber(split(":", target_ip.value)[1]) : 
  53  # Default to port 53 if conversion fails
)
```

## Networking Considerations

### VPC Association Strategy
**Plan VPC associations carefully** to avoid DNS resolution conflicts:

```hcl
# Best Practice: Explicit VPC-to-rule mapping
rules = [
  {
    domain_name = "prod.company.com."
    vpc_ids     = ["vpc-prod-1", "vpc-prod-2"]
    ips         = ["10.1.0.10", "10.1.0.11"]
  },
  {
    domain_name = "dev.company.com."
    vpc_ids     = ["vpc-dev-1"]
    ips         = ["10.2.0.10"]
  }
]
```

### DNS Resolution Hierarchy
**Understand Route53 Resolver resolution order:**
1. Route53 private hosted zones (highest priority)
2. Route53 Resolver rules (conditional forwarding)
3. VPC DNS resolver (lowest priority)

### Network Security Considerations
**Ensure proper network connectivity:**
- Resolver endpoints must be in subnets with routes to target DNS servers
- Security groups must allow outbound DNS traffic (port 53/UDP and 53/TCP)
- NACLs should permit DNS traffic between resolver endpoints and target servers

```hcl
# Example: Security group for resolver endpoint
resource "aws_security_group" "resolver_endpoint" {
  name_prefix = "route53-resolver-"
  vpc_id      = var.vpc_id

  egress {
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["10.0.1.0/24", "10.0.2.0/24"]  # Specific subnets only
  }

  egress {
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = ["10.0.1.0/24", "10.0.2.0/24"]
  }
}
```

## RAM Sharing Best Practices

### Cross-Account DNS Management
**Use RAM sharing for centralized DNS governance:**

```hcl
# Central DNS account creates and shares rules
rules = [
  {
    domain_name = "shared.company.com."
    vpc_ids     = ["vpc-central-123"]
    ips         = ["10.0.100.10", "10.0.100.11"]
    principals  = [
      "111122223333",  # Production account
      "444455556666",  # Development account
      "777788889999"   # Staging account
    ]
  }
]
```

### RAM Resource Naming Strategy
**Use consistent naming for RAM resources:**

```hcl
# Good: Descriptive RAM resource names
ram_name = "dns-${var.environment}-${replace(domain_name, ".", "-")}"

# Example outputs:
# "dns-prod-internal-company-com"
# "dns-dev-api-company-com"
```

### Principal Management
**Validate account IDs** to prevent sharing with unintended accounts:

```hcl
variable "trusted_accounts" {
  description = "List of AWS account IDs allowed to access shared DNS rules"
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for account in var.trusted_accounts : 
      can(regex("^[0-9]{12}$", account))
    ])
    error_message = "Account IDs must be exactly 12 digits."
  }
}
```

## Endpoint Management

### Resolver Endpoint Requirements
**Coordinate with resolver endpoint modules:**

```hcl
# Example: Using with external endpoint module
module "resolver_endpoint" {
  source = "git::https://github.com/rhythmictech/terraform-aws-route53-endpoint?ref=v1.0.0"
  
  direction         = "outbound"
  vpc_id           = var.vpc_id
  allowed_resolvers = var.allowed_resolver_cidrs
  
  ip_addresses = [
    {
      ip        = "10.0.1.10"
      subnet_id = var.private_subnet_ids[0]
    },
    {
      ip        = "10.0.2.10"
      subnet_id = var.private_subnet_ids[1]
    }
  ]
}

module "resolver_rules" {
  source = "./terraform-aws-route53-resolver-rules"
  
  resolver_endpoint_id = module.resolver_endpoint.endpoint_id
  rules               = var.dns_forwarding_rules
}
```

### Endpoint High Availability
**Design endpoints for fault tolerance:**
- Deploy endpoint IP addresses across multiple Availability Zones
- Use at least 2 IP addresses per endpoint for redundancy
- Consider geographically distributed endpoints for disaster recovery

## Variables & Validation

### Rule Structure Validation
**Implement comprehensive validation for rule inputs:**

```hcl
variable "rules" {
  description = "List of Route53 resolver rules for DNS forwarding"
  type = list(object({
    rule_name   = optional(string)
    domain_name = string
    ram_name    = optional(string)
    vpc_ids     = list(string)
    ips         = list(string)
    principals  = optional(list(string), [])
  }))
  default = []

  validation {
    condition = alltrue([
      for rule in var.rules : 
      can(regex("\\.$", rule.domain_name))
    ])
    error_message = "Domain names must end with a dot (.) to be fully qualified."
  }

  validation {
    condition = alltrue([
      for rule in var.rules : 
      length(rule.vpc_ids) > 0
    ])
    error_message = "Each rule must be associated with at least one VPC."
  }

  validation {
    condition = alltrue([
      for rule in var.rules : alltrue([
        for ip in rule.ips : 
        can(regex("^(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?::[1-9]|[1-9][0-9]|[1-9][0-9]{2}|[1-9][0-9]{3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])?$", ip))
      ])
    ])
    error_message = "IP addresses must be in valid IPv4 format, optionally with port (e.g., '192.168.1.1' or '192.168.1.1:5353')."
  }
}
```

### Resolver Endpoint Validation
```hcl
variable "resolver_endpoint_id" {
  description = "The ID of the outbound resolver endpoint for DNS forwarding"
  type        = string
  
  validation {
    condition     = can(regex("^rslvr-out-[0-9a-z]+$", var.resolver_endpoint_id))
    error_message = "Resolver endpoint ID must be a valid outbound endpoint ID starting with 'rslvr-out-'."
  }
}
```

## Testing Requirements

### Test Coverage for DNS Functionality
**Write comprehensive tests for DNS resolution:**
- Test rule creation and association with VPCs
- Validate DNS forwarding to target IP addresses
- Test RAM sharing across multiple accounts
- Verify rule deletion and cleanup
- Test DNS query response times and performance
- Validate security group and network connectivity

### Testing Strategy & Framework
**Multi-layered testing approach with Terratest:**
1. **Unit Tests**: Terraform validation and formatting
2. **Integration Tests**: Resource creation and DNS resolution
3. **End-to-End Tests**: Cross-account sharing and VPC association
4. **Performance Tests**: DNS query response times
5. **Security Tests**: Validate proper access controls and encryption

#### Test Directory Structure
```
test/
├── go.mod                                    # Go module dependencies
├── go.sum                                    # Go module checksums
├── helpers.go                                # Test helper functions
├── terraform_aws_route53_resolver_test.go   # Main integration tests
├── terraform_validation_test.go             # Validation and linting tests
├── terraform_dns_resolution_test.go         # DNS functionality tests
└── cleanup/
    └── main.go                               # Cleanup utility for test resources
```

#### Test Categories

**1. Validation Tests (`terraform_validation_test.go`)**
- `TestTerraformFormat` - Validates Terraform formatting
- `TestTerraformValidate` - Validates Terraform configuration syntax
- `TestExamplesValidation` - Validates all example configurations
- `TestTerraformPlan` - Tests that plan executes without errors
- `TestVariableValidation` - Tests input variable validation rules

**2. Integration Tests (`terraform_aws_route53_resolver_test.go`)**
- `TestTerraformRoute53ResolverBasic` - Basic rule creation functionality
- `TestTerraformRoute53ResolverMultipleRules` - Multiple DNS rules
- `TestTerraformRoute53ResolverVPCAssociation` - VPC association testing
- `TestTerraformRoute53ResolverRAMSharing` - Cross-account sharing
- `TestTerraformRoute53ResolverIPFormats` - IP address and port handling

**3. DNS Resolution Tests (`terraform_dns_resolution_test.go`)**
- `TestDNSForwardingFunctionality` - End-to-end DNS resolution
- `TestDNSQueryPerformance` - Response time validation
- `TestDNSFailoverScenarios` - Multiple target IP handling
- `TestDNSSecurityGroupValidation` - Network connectivity tests

### Running Tests Locally

#### Prerequisites
```bash
# Install Go (version 1.21 or later)
go version

# Install Terraform (version 1.0 or later)
terraform version

# Configure AWS credentials
aws configure
```

#### Test Execution Commands

**Run all tests:**
```bash
cd test
go test -v -timeout 45m ./...
```

**Run specific test suites:**
```bash
# Validation tests only (fast)
go test -v -timeout 10m -run "TestTerraform.*Validation|TestTerraformFormat"

# DNS resolution tests only
go test -v -timeout 30m -run "TestDNS.*"

# Integration tests only
go test -v -timeout 45m -run "TestTerraformRoute53Resolver.*"
```

**Run tests with specific patterns:**
```bash
# Test RAM sharing functionality
go test -v -run ".*RAM.*"

# Test validation only
go test -v -run ".*Validation.*"
```

### Test Environment Setup
```bash
# Required environment variables
export AWS_DEFAULT_REGION=us-east-1
export TEST_VPC_ID=vpc-test123456
export TEST_SUBNET_IDS=subnet-test1,subnet-test2
export TEST_DNS_SERVERS=10.0.100.10,10.0.100.11
export TEST_ACCOUNT_ID=123456789012

# Optional test configuration
export TF_VAR_test_suffix=test-$(date +%s)  # Unique suffix for resources
export AWS_PROFILE=your-profile             # AWS profile if using multiple
```

### DNS Resolution Testing
**Verify DNS forwarding functionality:**

```bash
# Test DNS resolution from VPC instances
dig @169.254.169.253 test.internal.company.com.

# Verify resolver rule creation
aws route53resolver list-resolver-rules \
  --filters Name=Name,Values=test-rule

# Check VPC associations
aws route53resolver list-resolver-rule-associations \
  --filters Name=ResolverRuleId,Values=rslvr-rr-12345

# Test target IP connectivity
nc -zvu 10.0.100.10 53  # Test UDP DNS port
nc -zv 10.0.100.10 53   # Test TCP DNS port
```

### Test Helper Functions

#### Common Utilities (`helpers.go`)
```go
// Generate unique test names
GenerateTestName(prefix string) string

// Get stable test regions
GetTestRegion(t *testing.T) string

// Validate resolver rules exist in AWS
ValidateResolverRuleExists(t *testing.T, region, ruleId string)

// Check DNS resolution functionality
ValidateDNSResolution(t *testing.T, domain, expectedIP string) bool

// Validate VPC associations
ValidateVPCAssociation(t *testing.T, region, ruleId, vpcId string)

// Validate RAM sharing
ValidateRAMSharing(t *testing.T, region, shareArn string, principals []string)

// Configuration builders
CreateBasicResolverConfig(rules []ResolverRule) map[string]interface{}
CreateMultiVPCConfig(rules []ResolverRule, vpcIds []string) map[string]interface{}
```

### CI/CD Pipeline

#### GitHub Actions Workflow (`.github/workflows/test.yml`)

**Pipeline Jobs:**

**1. Validate Job**
- Terraform format checking (`terraform fmt -check`)
- Terraform configuration validation
- Example configuration validation
- Runs on every push and pull request

**2. Security Job**
- Security scanning with `tfsec`
- Policy validation with `Checkov`
- DNS security rule validation
- Runs on every push and pull request

**3. Lint Job**
- Advanced linting with `TFLint`
- DNS-specific rule checking
- Custom validation for Route53 patterns
- Runs on every push and pull request

**4. Unit Tests Job**
- Validation and DNS functionality tests
- Matrix strategy for parallel execution
- Requires AWS credentials (secrets)
- Runs on pull requests and master branch

**5. Integration Tests Job**
- Full integration testing across multiple AWS regions
- DNS resolution and cross-account sharing tests
- Only runs on master branch or with `run-integration-tests` label

**6. Cleanup Job**
- Automatic cleanup of test resources
- DNS rule and VPC association cleanup
- Prevents resource leakage and cost accumulation

## Security Considerations

### DNS Security Best Practices
- **DNS over HTTPS (DoH)** or **DNS over TLS (DoT)** for sensitive environments
- **DNS filtering** to block malicious domains
- **Logging and monitoring** of DNS queries for security analysis
- **Access controls** via security groups and NACLs
- **Network segmentation** for DNS traffic isolation
- **Least privilege** access for RAM sharing principals

### Network Security Patterns
**Implement comprehensive network controls:**

```hcl
# Example: Security group for resolver endpoint traffic
variable "resolver_security_group_rules" {
  description = "Security group rules for resolver endpoint access"
  type = list(object({
    type        = string
    from_port   = number
    to_port     = number
    protocol    = string
    cidr_blocks = list(string)
    description = string
  }))
  default = [
    {
      type        = "egress"
      from_port   = 53
      to_port     = 53
      protocol    = "udp"
      cidr_blocks = ["10.0.1.0/24", "10.0.2.0/24"]
      description = "DNS UDP traffic to internal networks"
    },
    {
      type        = "egress"
      from_port   = 53
      to_port     = 53
      protocol    = "tcp"
      cidr_blocks = ["10.0.1.0/24", "10.0.2.0/24"]
      description = "DNS TCP traffic to internal networks"
    }
  ]
}
```

### Network Segmentation
```hcl
# Example: Restrict DNS forwarding to specific networks
variable "allowed_dns_networks" {
  description = "CIDR blocks allowed to use DNS forwarding"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]  # Use specific subnets instead of broad ranges

  validation {
    condition = alltrue([
      for cidr in var.allowed_dns_networks : 
      can(cidrhost(cidr, 0))
    ])
    error_message = "All elements must be valid CIDR blocks."
  }
}

# Validate internal IP ranges for DNS targets
variable "internal_dns_servers" {
  description = "List of internal DNS server IP addresses"
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for ip in var.internal_dns_servers : 
      can(regex("^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)", split(":", ip)[0]))
    ])
    error_message = "DNS servers should use private IP address ranges (RFC 1918)."
  }
}
```

### RAM Sharing Security
**Implement secure cross-account sharing:**

```hcl
# Example: Secure RAM principal validation
variable "trusted_principals" {
  description = "List of trusted AWS account IDs for RAM sharing"
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for account in var.trusted_principals : 
      can(regex("^[0-9]{12}$", account))
    ])
    error_message = "Principal IDs must be exactly 12 digits (AWS account IDs)."
  }

  # Note: Additional validation for same-account sharing should be implemented
  # at the resource level using locals or data sources within the module context
}

# Prevent sharing with external principals
variable "allow_external_principals" {
  description = "Whether to allow sharing with principals outside the organization"
  type        = bool
  default     = false

}
```

### Audit and Compliance
**Implement DNS query logging and monitoring:**

```hcl
# Example: Comprehensive DNS monitoring
resource "aws_cloudwatch_log_group" "dns_query_logs" {
  count             = var.enable_query_logging ? 1 : 0
  name              = "/aws/route53resolver/query-logs"
  retention_in_days = var.log_retention_days

  kms_key_id = var.log_encryption_key_arn

  tags = merge(local.dns_security_tags, {
    Purpose = "DNS-Query-Logging"
  })
}

# CloudWatch alarms for DNS security monitoring
resource "aws_cloudwatch_metric_alarm" "dns_query_rate" {
  count = var.enable_dns_monitoring ? 1 : 0

  alarm_name          = "route53-resolver-high-query-rate"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "QueryCount"
  namespace           = "AWS/Route53Resolver"
  period              = "300"
  statistic           = "Sum"
  threshold           = var.dns_query_threshold
  alarm_description   = "High DNS query rate detected"

  alarm_actions = var.sns_alarm_topic_arn != "" ? [var.sns_alarm_topic_arn] : []

  tags = local.dns_security_tags
}
```

## Module Development Guidelines

### Backward Compatibility
- Maintain existing rule structure interfaces
- Support legacy IP address formats
- Provide migration paths for breaking changes
- Document version-specific DNS behavior changes

### Performance Optimization
**Optimize for DNS resolution speed:**
- Minimize rule processing complexity
- Use efficient local transformations
- Consider DNS caching implications
- Monitor resolver endpoint performance

### Code Quality Standards
- Run `terraform fmt` before committing
- Use `terraform validate` for syntax checking
- Implement pre-commit hooks for DNS rule validation
- Use consistent naming for DNS-related resources

## Specific Module Patterns

### Multi-Rule Processing
**Efficient rule processing with locals:**

```hcl
locals {
  # Process rules with defaults - optimized with direct attribute access
  rules = [
    for rule in var.rules : {
      rule_name   = coalesce(rule.rule_name, "${rule.domain_name}-rule")
      domain_name = rule.domain_name
      ram_name    = coalesce(rule.ram_name, "r53-${rule.domain_name}")
      vpc_ids     = rule.vpc_ids
      ips         = rule.ips
      principals  = coalesce(rule.principals, [])
    }
  ]

  # Optimized single-pass flattening for VPC and RAM associations
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

  ram_associations = {
    for pair in flatten([
      for rule in var.rules : [
        for principal in rule.principals : {
          key          = "${rule.domain_name}-${principal}"
          principal_id = principal
          ram_name     = coalesce(rule.ram_name, rule.domain_name)
        }
      ] if length(rule.principals) > 0
    ]) : pair.key => pair
  }
}
```

### Resource Dependencies
**Manage complex resource dependencies:**

```hcl
# Use for_each for safer resource creation
resource "aws_route53_resolver_rule_association" "ra" {
  for_each = local.vpcs_associations
  
  resolver_rule_id = aws_route53_resolver_rule.r[each.value.domain_name].id
  vpc_id          = each.value.vpc_id

  depends_on = [aws_route53_resolver_rule.r]
}
```

## Development Workflow

### Pre-commit Requirements
**Run comprehensive checks before committing:**
- Run `terraform fmt` on modified files only
- Execute `terraform validate` for syntax checking
- Run `pre-commit run --files` on modified files
- Test DNS rule configuration with sample data
- Validate domain name formats and IP addresses
- Run security scanning for DNS-related vulnerabilities
- Execute unit tests for affected functionality

### DNS Testing Workflow
**Comprehensive testing approach:**
1. **Validate Configuration**: Check rule syntax and formats
2. **Deploy Infrastructure**: Create resolver rules and associations
3. **Test DNS Resolution**: Verify forwarding to target servers
4. **Test Cross-Account Sharing**: Validate RAM resource access
5. **Performance Testing**: Measure DNS query response times
6. **Security Testing**: Validate network controls and access patterns
7. **Cleanup**: Remove test resources and associations

```bash
# Example testing workflow
cd test/
go test -v -timeout 30m -run "TestTerraformValidation.*"
go test -v -timeout 45m -run "TestTerraformRoute53Resolver.*"
go test -v -timeout 30m -run "TestDNS.*"
```

### Release Management
**Follow conventional commit patterns for automated releases:**

```bash
# Examples of proper commit messages
feat: add support for DNS query logging configuration
fix: resolve VPC association dependency issues
docs: update Route53 Resolver patterns documentation
chore: update AWS provider version constraints
```

**Release Process:**
- **DO NOT manually update CHANGELOG.md** - use release-please for automated changelog generation
- Use conventional commit messages for proper release automation
- Follow semantic versioning principles in commit messages
- Test backward compatibility with existing DNS configurations
- Validate all examples before releasing
- Run full integration test suite

### Documentation Standards
**Maintain comprehensive documentation:**
- Document all variables with clear descriptions and validation rules
- Include examples for complex variable structures in variables.tf
- Update README.md for new features and breaking changes
- Let release-please handle version history automatically
- Include migration guides for breaking changes

### Code Quality Standards
**Enforce consistent quality across the module:**

```bash
# Pre-commit hooks for quality assurance
terraform fmt -check -recursive .
terraform validate
tflint --config=.tflint.hcl
tfsec . --config-file .tfsec.yml
checkov -d . --framework terraform
```

**Quality Guidelines:**
- Use descriptive variable names that reflect DNS concepts
- Implement comprehensive validation for DNS-specific inputs
- Follow consistent naming conventions for DNS resources
- Include meaningful descriptions for all outputs
- Use locals to simplify complex DNS rule processing logic

## Common DNS Patterns to Consider

1. **Conditional Forwarding** - Route specific domains to designated DNS servers
2. **Hybrid DNS** - Combine on-premises and cloud DNS resolution
3. **Multi-Account DNS** - Centralized DNS management across AWS accounts
4. **DNS Failover** - Multiple target IPs for high availability
5. **Environment Separation** - Different DNS rules per environment
6. **Domain Hierarchy** - Parent and child domain forwarding strategies
7. **DNS Caching** - Optimize for query performance and cost
8. **Monitoring and Alerting** - Track DNS resolution health and performance

## Provider Version Management

```hcl
terraform {
  required_version = ">= 1.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.0"
    }
  }
}
```

## Troubleshooting DNS Issues

### Common DNS Resolution Problems
1. **Missing trailing dots** in domain names
2. **Incorrect IP addresses** or unreachable DNS servers  
3. **Security group restrictions** blocking DNS traffic
4. **VPC association conflicts** with existing rules
5. **RAM sharing permissions** issues across accounts

### Diagnostic Commands
```bash
# Check resolver rule status
aws route53resolver get-resolver-rule --resolver-rule-id rslvr-rr-12345

# List VPC associations
aws route53resolver list-resolver-rule-associations

# Test DNS resolution
nslookup internal.company.com 169.254.169.253

# Check resolver endpoint health
aws route53resolver get-resolver-endpoint --resolver-endpoint-id rslvr-out-12345
```

*Note: This module focuses on DNS forwarding rules and requires coordination with Route53 Resolver endpoints for complete DNS resolution functionality.*