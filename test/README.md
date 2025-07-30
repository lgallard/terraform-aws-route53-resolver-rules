# Terraform AWS Route53 Resolver Rules - Test Suite

This directory contains comprehensive tests for the `terraform-aws-route53-resolver-rules` module using [Terratest](https://github.com/gruntwork-io/terratest).

## Test Structure

### Test Files

- **`terraform_route53_resolver_test.go`** - Main integration tests for Route53 resolver rules functionality
- **`terraform_validation_test.go`** - Validation tests for input parameters and edge cases
- **`helpers.go`** - Common helper functions and utilities for testing

### Test Categories

#### Integration Tests (`terraform_route53_resolver_test.go`)

1. **Basic Functionality**
   - `TestTerraformRoute53ResolverRulesBasic` - Tests basic resolver rule creation
   - `TestTerraformRoute53ResolverRulesMultipleRules` - Tests multiple resolver rules
   - `TestTerraformRoute53ResolverRulesWithRAM` - Tests RAM resource sharing
   - `TestTerraformRoute53ResolverRulesCustomPorts` - Tests custom DNS ports
   - `TestTerraformRoute53ResolverRulesOutputs` - Tests module outputs
   - `TestTerraformRoute53ResolverRulesTags` - Tests resource tagging
   - `TestTerraformRoute53ResolverRulesComplexScenario` - Tests complex multi-rule scenarios

2. **Real Resource Integration**
   - `TestTerraformRoute53ResolverRulesWithRealResources` - Tests with actual AWS resources (optional)

#### Validation Tests (`terraform_validation_test.go`)

1. **Configuration Validation**
   - `TestTerraformRoute53ResolverRulesValidation` - Tests various valid configurations
   - `TestTerraformRoute53ResolverRulesVariableTypes` - Tests variable type validation
   - `TestTerraformRoute53ResolverRulesLocalValues` - Tests local value calculations
   - `TestTerraformRoute53ResolverRulesEdgeCases` - Tests edge cases and boundary conditions

## Prerequisites

### Required Tools

- **Go** 1.23.0 or later
- **Terraform** 0.12 or later
- **AWS CLI** configured with appropriate credentials

### AWS Permissions

The test suite requires the following AWS permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "route53resolver:*",
                "ram:*",
                "ec2:CreateSecurityGroup",
                "ec2:DescribeSecurityGroups",
                "ec2:DeleteSecurityGroup",
                "ec2:DescribeVpcs",
                "ec2:DescribeSubnets"
            ],
            "Resource": "*"
        }
    ]
}
```

## Running Tests

### Setup

1. **Install Dependencies**
   ```bash
   cd test
   go mod tidy
   ```

2. **Configure AWS Credentials**
   ```bash
   export AWS_ACCESS_KEY_ID="your-access-key"
   export AWS_SECRET_ACCESS_KEY="your-secret-key"  # pragma: allowlist secret
   export AWS_DEFAULT_REGION="us-west-2"
   ```

### Test Execution

#### Run All Tests
```bash
cd test
go test -v -timeout 30m
```

#### Run Specific Test Files
```bash
# Integration tests only
go test -v -run "TestTerraformRoute53Resolver" -timeout 30m

# Validation tests only
go test -v -run "TestTerraformRoute53ResolverRulesValidation" -timeout 15m
```

#### Run Individual Tests
```bash
# Basic functionality test
go test -v -run "TestTerraformRoute53ResolverRulesBasic" -timeout 10m

# Complex scenario test
go test -v -run "TestTerraformRoute53ResolverRulesComplexScenario" -timeout 15m
```

#### Run Tests in Parallel
```bash
# Run tests with parallelism
go test -v -parallel 4 -timeout 45m
```

### Integration Tests with Real Resources

To run integration tests that create actual AWS resources:

```bash
# Enable integration tests
export INTEGRATION_TEST=true
go test -v -run "TestTerraformRoute53ResolverRulesWithRealResources" -timeout 30m
```

**Warning**: Integration tests will create real AWS resources and may incur costs.

## Test Configuration

### Environment Variables

- `AWS_DEFAULT_REGION` - AWS region for testing (default: random stable region)
- `INTEGRATION_TEST` - Set to "true" to enable integration tests with real resources
- `TERRATEST_LOG_LEVEL` - Terratest logging level (DEBUG, INFO, WARN, ERROR)

### Test Data

Tests use dynamically generated data to avoid conflicts:
- Unique IDs are generated for each test run
- Random AWS regions are selected for geographic distribution
- Test resources are tagged with identifiable markers

## Helper Functions

### Core Helpers (`helpers.go`)

- **`GenerateTestName(prefix)`** - Generates unique test names
- **`GetTestRegion(t)`** - Returns a random stable AWS region
- **`ValidateResolverRuleExists(t, region, ruleID)`** - Validates resolver rule existence
- **`ValidateResolverRuleAssociation(t, region, ruleID, vpcID)`** - Validates VPC associations
- **`ValidateRAMResourceShare(t, region, shareArn, principals)`** - Validates RAM sharing
- **`ValidateDNSResolution(t, domain, expectedIPs)`** - Tests DNS resolution
- **`WaitForResolverRuleDeletion(t, region, ruleID, maxRetries, sleepBetweenRetries)`** - Waits for cleanup

### Configuration Helpers

- **`CreateBasicResolverRuleConfig(domain, targetIPs, vpcIDs)`** - Basic rule configuration
- **`CreateCompleteResolverRuleConfig(domain, ruleName, ramName, targetIPs, vpcIDs, principals)`** - Complete rule configuration
- **`GetCommonTestVars(uniqueID)`** - Common test variables

### AWS Resource Helpers

- **`CreateMockResolverEndpoint(t, region, vpcID, subnetIDs)`** - Creates test resolver endpoint
- **`CleanupTestResolverRules(t, region, namePrefix)`** - Cleanup helper for resolver rules

## Test Scenarios

### Basic Scenarios

1. **Simple Resolver Rule**
   - Single domain with single target IP
   - Single VPC association
   - No RAM sharing

2. **Multiple Rules**
   - Multiple domains with different target IPs
   - Different VPC associations per rule
   - Mixed port configurations

3. **Custom Ports**
   - Target IPs with custom DNS ports
   - Mixed standard and custom ports

### Advanced Scenarios

1. **RAM Resource Sharing**
   - Cross-account principal sharing
   - Multiple principals per rule
   - Resource share validation

2. **Complex Multi-Rule Setup**
   - Multiple rules with different configurations
   - Mixed VPC associations
   - Combined RAM sharing and VPC associations

3. **Edge Cases**
   - Single IP address
   - Empty VPC lists
   - High port numbers (65535)
   - Complex domain names

## Troubleshooting

### Common Issues

1. **Permission Errors**
   - Ensure AWS credentials have required permissions
   - Check IAM policies for Route53 Resolver and RAM access

2. **Resource Conflicts**
   - Tests use unique IDs to avoid conflicts
   - Check for leftover resources from previous test runs

3. **Timeout Issues**
   - Increase test timeout for slow AWS API responses
   - Some operations (like resolver endpoint creation) can take several minutes

4. **DNS Resolution Tests**
   - DNS resolution tests may fail in test environments
   - These are marked as warnings rather than errors

### Debugging

Enable debug logging:
```bash
export TERRATEST_LOG_LEVEL=DEBUG
go test -v -run "TestName" -timeout 30m
```

Check AWS resources:
```bash
# List resolver rules
aws route53resolver list-resolver-rules

# List RAM resource shares
aws ram get-resource-shares
```

### Cleanup

If tests fail and leave resources:
```bash
# Manual cleanup script (example)
aws route53resolver list-resolver-rules --query 'ResolverRules[?contains(Name, `test-`)].Id' --output text | \
xargs -I {} aws route53resolver delete-resolver-rule --resolver-rule-id {}
```

## Contributing

### Adding New Tests

1. **Integration Tests**: Add to `terraform_route53_resolver_test.go`
2. **Validation Tests**: Add to `terraform_validation_test.go`
3. **Helper Functions**: Add to `helpers.go`

### Test Naming Convention

- Use descriptive test names: `TestTerraformRoute53ResolverRules<Functionality>`
- Use parallel execution: `t.Parallel()` for independent tests
- Include test descriptions in struct comments

### Best Practices

1. **Use unique IDs** for all test resources
2. **Clean up resources** in defer statements
3. **Validate assumptions** before main test logic
4. **Use appropriate timeouts** for AWS operations
5. **Include meaningful assertions** with descriptive messages

## Test Coverage

The test suite covers:

- ✅ Basic resolver rule creation
- ✅ Multiple resolver rules
- ✅ VPC associations
- ✅ RAM resource sharing
- ✅ Custom DNS ports
- ✅ Resource tagging
- ✅ Input validation
- ✅ Variable type checking
- ✅ Edge cases and boundary conditions
- ✅ Module outputs
- ✅ Local value calculations
- ✅ Complex scenarios

## Continuous Integration

For CI/CD integration:

```yaml
# Example GitHub Actions workflow
- name: Run Terratest
  run: |
    cd test
    go mod tidy
    go test -v -timeout 30m -parallel 2
  env:
    AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
    AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
    AWS_DEFAULT_REGION: us-west-2
```
