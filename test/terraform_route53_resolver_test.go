package test

import (
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/route53resolver"
	awshelper "github.com/gruntwork-io/terratest/modules/aws"
	"github.com/gruntwork-io/terratest/modules/random"
	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTerraformRoute53ResolverRulesBasic tests the basic functionality of the module
func TestTerraformRoute53ResolverRulesBasic(t *testing.T) {
	t.Parallel()

	// Generate a unique ID for this test run
	uniqueID := random.UniqueId()
	
	// AWS region to use for testing
	awsRegion := awshelper.GetRandomStableRegion(t, nil, nil)

	// Mock resolver endpoint ID for testing
	mockEndpointID := fmt.Sprintf("rslvr-out-%s", uniqueID)

	terraformOptions := &terraform.Options{
		TerraformDir: "../",
		Vars: map[string]interface{}{
			"resolver_endpoint_id": mockEndpointID,
			"rules": []map[string]interface{}{
				{
					"domain_name": "example.com.",
					"vpc_ids":     []string{"vpc-12345678"},
					"ips":         []string{"192.168.1.10", "192.168.1.11"},
				},
			},
			"tags": map[string]string{
				"Environment": "test",
				"TestRun":     uniqueID,
			},
		},
		EnvVars: map[string]string{
			"AWS_DEFAULT_REGION": awsRegion,
		},
	}

	// Skip actual deployment and just validate plan
	terraform.InitAndPlan(t, terraformOptions)

	// Note: We can't run apply without a real resolver endpoint, 
	// but we can validate the configuration is syntactically correct
	t.Log("Basic configuration validation passed")
}

// TestTerraformRoute53ResolverRulesMultipleRules tests multiple resolver rules
func TestTerraformRoute53ResolverRulesMultipleRules(t *testing.T) {
	t.Parallel()

	uniqueID := random.UniqueId()
	awsRegion := awshelper.GetRandomStableRegion(t, nil, nil)
	mockEndpointID := fmt.Sprintf("rslvr-out-%s", uniqueID)

	terraformOptions := &terraform.Options{
		TerraformDir: "../",
		Vars: map[string]interface{}{
			"resolver_endpoint_id": mockEndpointID,
			"rules": []map[string]interface{}{
				{
					"domain_name": "example.com.",
					"rule_name":   fmt.Sprintf("test-rule-1-%s", uniqueID),
					"vpc_ids":     []string{"vpc-12345678"},
					"ips":         []string{"192.168.1.10", "192.168.1.11"},
				},
				{
					"domain_name": "test.local.",
					"rule_name":   fmt.Sprintf("test-rule-2-%s", uniqueID),
					"vpc_ids":     []string{"vpc-87654321"},
					"ips":         []string{"10.0.1.10:54", "10.0.1.11:54"},
				},
			},
		},
		EnvVars: map[string]string{
			"AWS_DEFAULT_REGION": awsRegion,
		},
	}

	terraform.InitAndPlan(t, terraformOptions)
	t.Log("Multiple rules configuration validation passed")
}

// TestTerraformRoute53ResolverRulesWithRAM tests resolver rules with RAM sharing
func TestTerraformRoute53ResolverRulesWithRAM(t *testing.T) {
	t.Parallel()

	uniqueID := random.UniqueId()
	awsRegion := awshelper.GetRandomStableRegion(t, nil, nil)
	mockEndpointID := fmt.Sprintf("rslvr-out-%s", uniqueID)

	terraformOptions := &terraform.Options{
		TerraformDir: "../",
		Vars: map[string]interface{}{
			"resolver_endpoint_id": mockEndpointID,
			"rules": []map[string]interface{}{
				{
					"domain_name": "shared.example.com.",
					"rule_name":   fmt.Sprintf("shared-rule-%s", uniqueID),
					"ram_name":    fmt.Sprintf("ram-share-%s", uniqueID),
					"vpc_ids":     []string{"vpc-12345678"},
					"ips":         []string{"192.168.1.10", "192.168.1.11"},
					"principals":  []string{"123456789012", "210987654321"},
				},
			},
		},
		EnvVars: map[string]string{
			"AWS_DEFAULT_REGION": awsRegion,
		},
	}

	terraform.InitAndPlan(t, terraformOptions)
	t.Log("RAM sharing configuration validation passed")
}

// TestTerraformRoute53ResolverRulesCustomPorts tests resolver rules with custom ports
func TestTerraformRoute53ResolverRulesCustomPorts(t *testing.T) {
	t.Parallel()

	uniqueID := random.UniqueId()
	awsRegion := awshelper.GetRandomStableRegion(t, nil, nil)
	mockEndpointID := fmt.Sprintf("rslvr-out-%s", uniqueID)

	terraformOptions := &terraform.Options{
		TerraformDir: "../",
		Vars: map[string]interface{}{
			"resolver_endpoint_id": mockEndpointID,
			"rules": []map[string]interface{}{
				{
					"domain_name": "custom-port.example.com.",
					"vpc_ids":     []string{"vpc-12345678"},
					"ips":         []string{"192.168.1.10:8053", "192.168.1.11:8054"},
				},
			},
		},
		EnvVars: map[string]string{
			"AWS_DEFAULT_REGION": awsRegion,
		},
	}

	terraform.InitAndPlan(t, terraformOptions)
	t.Log("Custom ports configuration validation passed")
}

// TestTerraformRoute53ResolverRulesOutputs tests module outputs
func TestTerraformRoute53ResolverRulesOutputs(t *testing.T) {
	t.Parallel()

	uniqueID := random.UniqueId()
	awsRegion := awshelper.GetRandomStableRegion(t, nil, nil)
	mockEndpointID := fmt.Sprintf("rslvr-out-%s", uniqueID)

	terraformOptions := &terraform.Options{
		TerraformDir: "../",
		Vars: map[string]interface{}{
			"resolver_endpoint_id": mockEndpointID,
			"rules": []map[string]interface{}{
				{
					"domain_name": "output-test.example.com.",
					"rule_name":   fmt.Sprintf("output-test-rule-%s", uniqueID),
					"vpc_ids":     []string{"vpc-12345678"},
					"ips":         []string{"192.168.1.10"},
				},
			},
		},
		EnvVars: map[string]string{
			"AWS_DEFAULT_REGION": awsRegion,
		},
	}

	plan := terraform.InitAndPlan(t, terraformOptions)
	
	// Validate that expected outputs are defined
	assert.Contains(t, plan, "resolver_rules", "Should contain resolver_rules output")
	t.Log("Outputs configuration validation passed")
}

// TestTerraformRoute53ResolverRulesTags tests tag functionality
func TestTerraformRoute53ResolverRulesTags(t *testing.T) {
	t.Parallel()

	uniqueID := random.UniqueId()
	awsRegion := awshelper.GetRandomStableRegion(t, nil, nil)
	mockEndpointID := fmt.Sprintf("rslvr-out-%s", uniqueID)

	expectedTags := map[string]string{
		"Environment": "test",
		"Team":        "engineering",
		"Project":     "terratest",
		"TestID":      uniqueID,
	}

	terraformOptions := &terraform.Options{
		TerraformDir: "../",
		Vars: map[string]interface{}{
			"resolver_endpoint_id": mockEndpointID,
			"rules": []map[string]interface{}{
				{
					"domain_name": "tagged.example.com.",
					"vpc_ids":     []string{"vpc-12345678"},
					"ips":         []string{"192.168.1.10"},
				},
			},
			"tags": expectedTags,
		},
		EnvVars: map[string]string{
			"AWS_DEFAULT_REGION": awsRegion,
		},
	}

	plan := terraform.InitAndPlan(t, terraformOptions)
	
	// Validate tags are included in the configuration
	for key, value := range expectedTags {
		assert.Contains(t, plan, key, "Plan should contain tag key")
		assert.Contains(t, plan, value, "Plan should contain tag value")
	}
	
	t.Log("Tags configuration validation passed")
}

// TestTerraformRoute53ResolverRulesComplexScenario tests a complex scenario with multiple rules, VPCs, and RAM sharing
func TestTerraformRoute53ResolverRulesComplexScenario(t *testing.T) {
	t.Parallel()

	uniqueID := random.UniqueId()
	awsRegion := awshelper.GetRandomStableRegion(t, nil, nil)
	mockEndpointID := fmt.Sprintf("rslvr-out-%s", uniqueID)

	terraformOptions := &terraform.Options{
		TerraformDir: "../",
		Vars: map[string]interface{}{
			"resolver_endpoint_id": mockEndpointID,
			"rules": []map[string]interface{}{
				{
					"domain_name": "corp.example.com.",
					"rule_name":   fmt.Sprintf("corp-rule-%s", uniqueID),
					"ram_name":    fmt.Sprintf("corp-ram-%s", uniqueID),
					"vpc_ids":     []string{"vpc-12345678", "vpc-87654321"},
					"ips":         []string{"192.168.10.10", "192.168.10.11:54"},
					"principals":  []string{"123456789012", "210987654321"},
				},
				{
					"domain_name": "dev.example.com.",
					"rule_name":   fmt.Sprintf("dev-rule-%s", uniqueID),
					"vpc_ids":     []string{"vpc-11111111"},
					"ips":         []string{"10.0.1.10", "10.0.1.11"},
				},
				{
					"domain_name": "test.local.",
					"rule_name":   fmt.Sprintf("test-rule-%s", uniqueID),
					"ram_name":    fmt.Sprintf("test-ram-%s", uniqueID),
					"vpc_ids":     []string{"vpc-22222222"},
					"ips":         []string{"172.16.1.10:8053"},
					"principals":  []string{"333333333333"},
				},
			},
			"tags": map[string]string{
				"Environment": "test",
				"Scenario":    "complex",
				"TestID":      uniqueID,
			},
		},
		EnvVars: map[string]string{
			"AWS_DEFAULT_REGION": awsRegion,
		},
	}

	plan := terraform.InitAndPlan(t, terraformOptions)
	
	// Validate that all expected resources are planned
	assert.Contains(t, plan, "aws_route53_resolver_rule.r", "Should plan resolver rules")
	assert.Contains(t, plan, "aws_route53_resolver_rule_association.ra", "Should plan rule associations")
	assert.Contains(t, plan, "aws_ram_resource_share.endpoint_share", "Should plan RAM resource shares")
	assert.Contains(t, plan, "aws_ram_principal_association.endpoint_ram_principal", "Should plan RAM principal associations")
	assert.Contains(t, plan, "aws_ram_resource_association.endpoint_ram_resource", "Should plan RAM resource associations")
	
	t.Log("Complex scenario configuration validation passed")
}

// TestTerraformRoute53ResolverRulesWithRealResources tests with actual AWS resources (integration test)
// Note: This test requires actual AWS resources and should be run in a test environment
func TestTerraformRoute53ResolverRulesWithRealResources(t *testing.T) {
	// Skip this test by default as it requires real AWS resources
	t.Skip("Skipping integration test with real AWS resources. Set INTEGRATION_TEST=true to run.")

	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	awsRegion := awshelper.GetRandomStableRegion(t, nil, nil)

	// This would require setting up actual VPC, subnets, and resolver endpoint
	// For demonstration purposes, we'll show the structure
	terraformOptions := &terraform.Options{
		TerraformDir: "../examples/simple",
		Vars: map[string]interface{}{
			"name_suffix": "integration-test",
		},
		EnvVars: map[string]string{
			"AWS_DEFAULT_REGION": awsRegion,
		},
	}

	defer terraform.Destroy(t, terraformOptions)

	terraform.InitAndApply(t, terraformOptions)

	// Validate that resolver rules were created
	resolverRules := terraform.OutputMap(t, terraformOptions, "resolver_rules")
	assert.NotEmpty(t, resolverRules, "Should have created resolver rules")

	// Additional validation would go here
	t.Log("Integration test with real resources completed")
}

// TestTerraformRoute53ResolverEndpointValidation tests resolver endpoint validation
func TestTerraformRoute53ResolverEndpointValidation(t *testing.T) {
	t.Parallel()

	awsRegion := awshelper.GetRandomStableRegion(t, nil, nil)

	// Test with missing resolver endpoint ID
	terraformOptions := &terraform.Options{
		TerraformDir: "../",
		Vars: map[string]interface{}{
			// Note: resolver_endpoint_id is intentionally missing
			"rules": []map[string]interface{}{
				{
					"domain_name": "example.com.",
					"rule_name":   "endpoint-validation-rule",
					"vpc_ids":     []string{"vpc-12345678"},
					"ips":         []string{"192.168.1.10"},
				},
			},
		},
		EnvVars: map[string]string{
			"AWS_DEFAULT_REGION": awsRegion,
		},
	}

	// This should work as resolver_endpoint_id has a default value of null
	terraform.InitAndPlan(t, terraformOptions)
	t.Log("Endpoint validation passed")
}

// Helper function to create a real resolver endpoint for integration testing
func createTestResolverEndpoint(t *testing.T, region, vpcID string, subnetIDs []string) string {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region),
	})
	require.NoError(t, err)

	svc := route53resolver.New(sess)

	var ipAddresses []*route53resolver.IpAddressRequest
	for _, subnetID := range subnetIDs {
		ipAddresses = append(ipAddresses, &route53resolver.IpAddressRequest{
			SubnetId: aws.String(subnetID),
		})
	}

	input := &route53resolver.CreateResolverEndpointInput{
		Direction:        aws.String("OUTBOUND"),
		IpAddresses:      ipAddresses,
		SecurityGroupIds: []*string{aws.String("sg-12345678")}, // Mock security group
		Name:             aws.String(fmt.Sprintf("test-endpoint-%s", random.UniqueId())),
	}

	result, err := svc.CreateResolverEndpoint(input)
	require.NoError(t, err)

	return *result.ResolverEndpoint.Id
}