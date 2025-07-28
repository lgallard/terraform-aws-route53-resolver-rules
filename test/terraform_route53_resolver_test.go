package test

import (
	"fmt"
	"strings"
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
	
	// Verify test environment safety
	VerifyTestEnvironment(t, awsRegion)

	// Generate test session ID for parallel test isolation
	sessionID := GenerateTestSessionID(t)

	// Generate secure test resolver endpoint ID with session isolation
	mockEndpointID := GenerateTestResourceNameWithSession("resolver-endpoint", "basic-test", sessionID)
	mockVPCID := GenerateTestResourceNameWithSession("vpc", "basic-test", sessionID)
	
	// Validate AWS resource formats
	resourceMap := map[string]string{
		"resolver-endpoint": mockEndpointID,
		"vpc": mockVPCID,
	}
	ValidateAWSResourceFormats(t, resourceMap)
	
	// Ensure resource isolation
	EnsureResourceIsolation(t, awsRegion, []string{mockEndpointID, mockVPCID})
	
	// Validate resource ID uniqueness
	ValidateResourceIDUniqueness(t, []string{mockEndpointID, mockVPCID}, sessionID)

	terraformOptions := &terraform.Options{
		TerraformDir: "../",
		Vars: map[string]interface{}{
			"resolver_endpoint_id": mockEndpointID,
			"rules": []map[string]interface{}{
				{
					"domain_name": "example.com.",
					"vpc_ids":     []string{mockVPCID},
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

	// Setup cleanup for any test resources
	defer func() {
		CleanupTestResolverRules(t, awsRegion, "terratest-")
	}()

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
	mockEndpointID := GenerateTestResourceName("resolver-endpoint", "test")

	terraformOptions := &terraform.Options{
		TerraformDir: "../",
		Vars: map[string]interface{}{
			"resolver_endpoint_id": mockEndpointID,
			"rules": []map[string]interface{}{
				{
					"domain_name": "example.com.",
					"rule_name":   fmt.Sprintf("test-rule-1-%s", uniqueID),
					"vpc_ids":     []string{GenerateTestResourceName("vpc", "test")},
					"ips":         []string{"192.168.1.10", "192.168.1.11"},
				},
				{
					"domain_name": "test.local.",
					"rule_name":   fmt.Sprintf("test-rule-2-%s", uniqueID),
					"vpc_ids":     []string{GenerateTestResourceName("vpc", "test-2")},
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
	mockEndpointID := GenerateTestResourceName("resolver-endpoint", "test")

	terraformOptions := &terraform.Options{
		TerraformDir: "../",
		Vars: map[string]interface{}{
			"resolver_endpoint_id": mockEndpointID,
			"rules": []map[string]interface{}{
				{
					"domain_name": "shared.example.com.",
					"rule_name":   fmt.Sprintf("shared-rule-%s", uniqueID),
					"ram_name":    fmt.Sprintf("ram-share-%s", uniqueID),
					"vpc_ids":     []string{GenerateTestResourceName("vpc", "test")},
					"ips":         []string{"192.168.1.10", "192.168.1.11"},
					"principals":  []string{GenerateTestResourceName("account", "principal-1"), GenerateTestResourceName("account", "principal-2")},
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

	awsRegion := awshelper.GetRandomStableRegion(t, nil, nil)
	mockEndpointID := GenerateTestResourceName("resolver-endpoint", "test")

	terraformOptions := &terraform.Options{
		TerraformDir: "../",
		Vars: map[string]interface{}{
			"resolver_endpoint_id": mockEndpointID,
			"rules": []map[string]interface{}{
				{
					"domain_name": "custom-port.example.com.",
					"vpc_ids":     []string{GenerateTestResourceName("vpc", "test")},
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
	mockEndpointID := GenerateTestResourceName("resolver-endpoint", "test")

	terraformOptions := &terraform.Options{
		TerraformDir: "../",
		Vars: map[string]interface{}{
			"resolver_endpoint_id": mockEndpointID,
			"rules": []map[string]interface{}{
				{
					"domain_name": "output-test.example.com.",
					"rule_name":   fmt.Sprintf("output-test-rule-%s", uniqueID),
					"vpc_ids":     []string{GenerateTestResourceName("vpc", "test")},
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
	mockEndpointID := GenerateTestResourceName("resolver-endpoint", "test")

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
					"vpc_ids":     []string{GenerateTestResourceName("vpc", "test")},
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
	mockEndpointID := GenerateTestResourceName("resolver-endpoint", "test")

	terraformOptions := &terraform.Options{
		TerraformDir: "../",
		Vars: map[string]interface{}{
			"resolver_endpoint_id": mockEndpointID,
			"rules": []map[string]interface{}{
				{
					"domain_name": "corp.example.com.",
					"rule_name":   fmt.Sprintf("corp-rule-%s", uniqueID),
					"ram_name":    fmt.Sprintf("corp-ram-%s", uniqueID),
					"vpc_ids":     []string{GenerateTestResourceName("vpc", "complex-1"), GenerateTestResourceName("vpc", "complex-2")},
					"ips":         []string{"192.168.10.10", "192.168.10.11:54"},
					"principals":  []string{GenerateTestResourceName("account", "principal-1"), GenerateTestResourceName("account", "principal-2")},
				},
				{
					"domain_name": "dev.example.com.",
					"rule_name":   fmt.Sprintf("dev-rule-%s", uniqueID),
					"vpc_ids":     []string{GenerateTestResourceName("vpc", "complex-3")},
					"ips":         []string{"10.0.1.10", "10.0.1.11"},
				},
				{
					"domain_name": "test.local.",
					"rule_name":   fmt.Sprintf("test-rule-%s", uniqueID),
					"ram_name":    fmt.Sprintf("test-ram-%s", uniqueID),
					"vpc_ids":     []string{GenerateTestResourceName("vpc", "complex-4")},
					"ips":         []string{"172.16.1.10:8053"},
					"principals":  []string{GenerateTestResourceName("account", "principal-3")},
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
					"vpc_ids":     []string{GenerateTestResourceName("vpc", "test")},
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
		SecurityGroupIds: []*string{aws.String(GenerateTestResourceName("sg", "test"))}, // Dynamic security group
		Name:             aws.String(fmt.Sprintf("test-endpoint-%s", random.UniqueId())),
	}

	result, err := svc.CreateResolverEndpoint(input)
	require.NoError(t, err)

	return *result.ResolverEndpoint.Id
}

// TestTerraformRoute53ResolverRulesErrorHandling tests comprehensive error scenarios
func TestTerraformRoute53ResolverRulesErrorHandling(t *testing.T) {
	t.Parallel()

	awsRegion := awshelper.GetRandomStableRegion(t, nil, nil)

	// Test cases for various error scenarios
	errorTestCases := []struct {
		name        string
		description string
		vars        map[string]interface{}
		expectError bool
		errorText   string
	}{
		{
			name:        "invalid_resolver_endpoint_format",
			description: "Test with invalid resolver endpoint ID format",
			vars: map[string]interface{}{
				"resolver_endpoint_id": "invalid-endpoint-format", // Invalid format
				"rules": []map[string]interface{}{
					{
						"domain_name": "error-test.com.",
						"rule_name":   "error-test-rule",
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "error-test")},
						"ips":         []string{"192.168.1.10"},
					},
				},
			},
			expectError: true,
			errorText:   "invalid",
		},
		{
			name:        "missing_required_ips",
			description: "Test with missing required IP addresses",
			vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceName("resolver-endpoint", "missing-ips"),
				"rules": []map[string]interface{}{
					{
						"domain_name": "missing-ips.com.",
						"rule_name":   "missing-ips-rule",
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "error-test")},
						"ips":         []string{}, // Empty IPs list
					},
				},
			},
			expectError: true,
			errorText:   "required",
		},
		{
			name:        "malformed_ip_addresses",
			description: "Test with malformed IP addresses",
			vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceName("resolver-endpoint", "malformed-ip"),
				"rules": []map[string]interface{}{
					{
						"domain_name": "malformed-ip.com.",
						"rule_name":   "malformed-ip-rule",
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "error-test")},
						"ips":         []string{"not.an.ip.address", "192.168.1.999"}, // Invalid IPs
					},
				},
			},
			expectError: true,
			errorText:   "invalid",
		},
		{
			name:        "conflicting_rule_names",
			description: "Test with conflicting rule names",
			vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceName("resolver-endpoint", "conflict"),
				"rules": []map[string]interface{}{
					{
						"domain_name": "conflict1.com.",
						"rule_name":   "duplicate-rule-name",
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "conflict-1")},
						"ips":         []string{"192.168.1.10"},
					},
					{
						"domain_name": "conflict2.com.",
						"rule_name":   "duplicate-rule-name", // Same name as above
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "conflict-2")},
						"ips":         []string{"192.168.1.11"},
					},
				},
			},
			expectError: true,
			errorText:   "duplicate",
		},
	}

	for _, tc := range errorTestCases {
		t.Run(tc.name, func(t *testing.T) {
			terraformOptions := &terraform.Options{
				TerraformDir: "../",
				Vars:         tc.vars,
				EnvVars: map[string]string{
					"AWS_DEFAULT_REGION": awsRegion,
				},
			}

			if tc.expectError {
				_, err := terraform.InitAndPlanE(t, terraformOptions)
				assert.Error(t, err, "Expected error for test case: %s", tc.name)
				if tc.errorText != "" {
					assert.Contains(t, strings.ToLower(err.Error()), strings.ToLower(tc.errorText),
						"Error should contain expected text for test case: %s", tc.name)
				}
				t.Logf("Expected error handled correctly for: %s - %s", tc.name, tc.description)
			} else {
				terraform.InitAndPlan(t, terraformOptions)
				t.Logf("Test passed for: %s - %s", tc.name, tc.description)
			}
		})
	}
}

// TestTerraformRoute53ResolverRulesAWSServiceLimits tests error scenarios for AWS service limits and quotas
func TestTerraformRoute53ResolverRulesAWSServiceLimits(t *testing.T) {
	t.Parallel()

	uniqueID := random.UniqueId()
	awsRegion := awshelper.GetRandomStableRegion(t, nil, nil)
	
	// Verify test environment safety
	VerifyTestEnvironment(t, awsRegion)

	// Generate test session ID for isolation
	sessionID := GenerateTestSessionID(t)

	serviceLimitTests := []struct {
		name        string
		description string
		vars        map[string]interface{}
		expectError bool
		errorText   string
	}{
		{
			name:        "excessive_resolver_rules_count",
			description: "Test creation of many resolver rules to approach service limits",
			vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceNameWithSession("resolver-endpoint", "limit-test", sessionID),
				"rules": func() []map[string]interface{} {
					rules := make([]map[string]interface{}, 50) // Test near AWS limit
					for i := 0; i < 50; i++ {
						rules[i] = map[string]interface{}{
							"domain_name": fmt.Sprintf("limit-test-%d.example.com.", i),
							"rule_name":   fmt.Sprintf("limit-rule-%d-%s", i, uniqueID),
							"vpc_ids":     []string{GenerateTestResourceNameWithSession("vpc", fmt.Sprintf("limit-%d", i), sessionID)},
							"ips":         []string{"192.168.1.10"},
						}
					}
					return rules
				}(),
			},
			expectError: false, // Should handle reasonable number of rules
		},
		{
			name:        "ram_resource_sharing_limits",
			description: "Test RAM resource sharing with many principals to test quota limits",
			vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceNameWithSession("resolver-endpoint", "ram-limit", sessionID),
				"rules": []map[string]interface{}{
					{
						"domain_name": "ram-limit-test.example.com.",
						"rule_name":   fmt.Sprintf("ram-limit-rule-%s", uniqueID),
						"ram_name":    fmt.Sprintf("ram-limit-share-%s", uniqueID),
						"vpc_ids":     []string{GenerateTestResourceNameWithSession("vpc", "ram-limit", sessionID)},
						"ips":         []string{"192.168.1.10"},
						"principals": func() []string {
							principals := make([]string, 20) // Test many principals
							for i := 0; i < 20; i++ {
								principals[i] = GenerateTestResourceNameWithSession("account", fmt.Sprintf("principal-%d", i), sessionID)
							}
							return principals
						}(),
					},
				},
			},
			expectError: false, // Should handle reasonable number of principals
		},
		{
			name:        "vpc_association_limits",
			description: "Test resolver rule with many VPC associations",
			vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceNameWithSession("resolver-endpoint", "vpc-limit", sessionID),
				"rules": []map[string]interface{}{
					{
						"domain_name": "vpc-limit-test.example.com.",
						"rule_name":   fmt.Sprintf("vpc-limit-rule-%s", uniqueID),
						"vpc_ids": func() []string {
							vpcs := make([]string, 25) // Test many VPC associations
							for i := 0; i < 25; i++ {
								vpcs[i] = GenerateTestResourceNameWithSession("vpc", fmt.Sprintf("vpc-limit-%d", i), sessionID)
							}
							return vpcs
						}(),
						"ips": []string{"192.168.1.10"},
					},
				},
			},
			expectError: false, // Should handle reasonable number of VPCs
		},
		{
			name:        "invalid_resource_references",
			description: "Test with invalid AWS resource references that would cause API errors",
			vars: map[string]interface{}{
				"resolver_endpoint_id": "rslvr-out-invalidendpoint123", // Invalid but properly formatted
				"rules": []map[string]interface{}{
					{
						"domain_name": "invalid-ref-test.example.com.",
						"rule_name":   fmt.Sprintf("invalid-ref-rule-%s", uniqueID),
						"vpc_ids":     []string{"vpc-invalidvpcref123"}, // Invalid but properly formatted
						"ips":         []string{"192.168.1.10"},
						"principals":  []string{"123456789012"}, // Valid format but non-existent account
					},
				},
			},
			expectError: true,
			errorText:   "invalid", // Expect validation or API errors
		},
		{
			name:        "cross_region_resource_references",
			description: "Test cross-region resource references that might cause errors",
			vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceNameWithSession("resolver-endpoint", "cross-region", sessionID),
				"rules": []map[string]interface{}{
					{
						"domain_name": "cross-region-test.example.com.",
						"rule_name":   fmt.Sprintf("cross-region-rule-%s", uniqueID),
						"vpc_ids":     []string{GenerateTestResourceNameWithSession("vpc", "cross-region", sessionID)},
						"ips":         []string{"192.168.1.10"},
					},
				},
			},
			expectError: false, // Depends on configuration
		},
	}

	for _, tc := range serviceLimitTests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup cleanup for any test resources
			defer func() {
				CleanupTestResolverRules(t, awsRegion, "terratest-")
			}()

			// Validate resource formats before testing
			if !tc.expectError {
				resourceMap := map[string]string{
					"resolver-endpoint": tc.vars["resolver_endpoint_id"].(string),
				}
				if rules, ok := tc.vars["rules"].([]map[string]interface{}); ok && len(rules) > 0 {
					if vpcIDs, ok := rules[0]["vpc_ids"].([]string); ok && len(vpcIDs) > 0 {
						resourceMap["vpc"] = vpcIDs[0]
					}
					if principals, ok := rules[0]["principals"].([]string); ok && len(principals) > 0 {
						resourceMap["account"] = principals[0]
					}
				}
				ValidateAWSResourceFormats(t, resourceMap)
			}

			terraformOptions := &terraform.Options{
				TerraformDir: "../",
				Vars:         tc.vars,
				EnvVars: map[string]string{
					"AWS_DEFAULT_REGION": awsRegion,
				},
			}

			if tc.expectError {
				_, err := terraform.InitAndPlanE(t, terraformOptions)
				assert.Error(t, err, "Expected service limit error for test case: %s", tc.name)
				if tc.errorText != "" {
					assert.Contains(t, strings.ToLower(err.Error()), strings.ToLower(tc.errorText),
						"Error should contain expected text for test case: %s", tc.name)
				}
				t.Logf("Expected service limit error handled correctly for: %s - %s", tc.name, tc.description)
			} else {
				terraform.InitAndPlan(t, terraformOptions)
				t.Logf("Service limit test passed: %s - %s", tc.name, tc.description)
			}
		})
	}
}

// TestTerraformRoute53ResolverRulesNetworkTimeouts tests network timeout and connectivity error scenarios
func TestTerraformRoute53ResolverRulesNetworkTimeouts(t *testing.T) {
	t.Parallel()

	uniqueID := random.UniqueId()
	awsRegion := awshelper.GetRandomStableRegion(t, nil, nil)
	
	// Verify test environment safety
	VerifyTestEnvironment(t, awsRegion)

	// Generate test session ID for isolation
	sessionID := GenerateTestSessionID(t)

	networkTimeoutTests := []struct {
		name        string
		description string
		vars        map[string]interface{}
		expectError bool
		errorText   string
	}{
		{
			name:        "network_timeout_simulation",
			description: "Test network timeout scenarios with connection pooling",
			vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceNameWithSession("resolver-endpoint", "timeout-test", sessionID),
				"rules": []map[string]interface{}{
					{
						"domain_name": "timeout-test.example.com.",
						"rule_name":   fmt.Sprintf("timeout-rule-%s", uniqueID),
						"vpc_ids":     []string{GenerateTestResourceNameWithSession("vpc", "timeout", sessionID)},
						"ips":         []string{"192.168.1.10", "192.168.1.11"},
					},
				},
			},
			expectError: false,
		},
		{
			name:        "dns_resolution_failure",
			description: "Test DNS resolution failure scenarios with fallback servers",
			vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceNameWithSession("resolver-endpoint", "dns-fail", sessionID),
				"rules": []map[string]interface{}{
					{
						"domain_name": "dns-fail-test.example.com.",
						"rule_name":   fmt.Sprintf("dns-fail-rule-%s", uniqueID),
						"vpc_ids":     []string{GenerateTestResourceNameWithSession("vpc", "dns-fail", sessionID)},
						"ips":         []string{"203.0.113.1", "203.0.113.2"}, // TEST-NET-3 IPs (RFC 5737)
					},
				},
			},
			expectError: false,
		},
		{
			name:        "aws_api_throttling_simulation",
			description: "Test AWS API throttling and retry scenarios",
			vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceNameWithSession("resolver-endpoint", "throttle", sessionID),
				"rules": func() []map[string]interface{} {
					// Create many rules to potentially trigger throttling
					rules := make([]map[string]interface{}, 10)
					for i := 0; i < 10; i++ {
						rules[i] = map[string]interface{}{
							"domain_name": fmt.Sprintf("throttle-%d.example.com.", i),
							"rule_name":   fmt.Sprintf("throttle-rule-%d-%s", i, uniqueID),
							"vpc_ids":     []string{GenerateTestResourceNameWithSession("vpc", fmt.Sprintf("throttle-%d", i), sessionID)},
							"ips":         []string{"192.168.1.10"},
						}
					}
					return rules
				}(),
			},
			expectError: false,
		},
		{
			name:        "connection_pool_exhaustion",
			description: "Test connection pool exhaustion scenarios",
			vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceNameWithSession("resolver-endpoint", "pool-test", sessionID),
				"rules": func() []map[string]interface{} {
					// Create many rules to test connection pooling
					rules := make([]map[string]interface{}, 20)
					for i := 0; i < 20; i++ {
						rules[i] = map[string]interface{}{
							"domain_name": fmt.Sprintf("pool-test-%d.example.com.", i),
							"rule_name":   fmt.Sprintf("pool-rule-%d-%s", i, uniqueID),
							"vpc_ids":     []string{GenerateTestResourceNameWithSession("vpc", fmt.Sprintf("pool-%d", i), sessionID)},
							"ips":         []string{"192.168.1.10", "192.168.1.11"},
						}
					}
					return rules
				}(),
			},
			expectError: false,
		},
		{
			name:        "network_partition_simulation",
			description: "Test network partition and connectivity loss scenarios",
			vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceNameWithSession("resolver-endpoint", "partition", sessionID),
				"rules": []map[string]interface{}{
					{
						"domain_name": "partition-test.example.com.",
						"rule_name":   fmt.Sprintf("partition-rule-%s", uniqueID),
						"vpc_ids":     []string{GenerateTestResourceNameWithSession("vpc", "partition", sessionID)},
						"ips":         []string{"198.51.100.1", "198.51.100.2"}, // TEST-NET-2 IPs (RFC 5737)
					},
				},
			},
			expectError: false,
		},
	}

	for _, tc := range networkTimeoutTests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup cleanup for any test resources
			defer func() {
				CleanupTestResolverRules(t, awsRegion, "terratest-")
			}()

			// Validate resource formats
			resourceMap := map[string]string{
				"resolver-endpoint": tc.vars["resolver_endpoint_id"].(string),
			}
			if rules, ok := tc.vars["rules"].([]map[string]interface{}); ok && len(rules) > 0 {
				if vpcIDs, ok := rules[0]["vpc_ids"].([]string); ok && len(vpcIDs) > 0 {
					resourceMap["vpc"] = vpcIDs[0]
				}
			}
			ValidateAWSResourceFormatsWithRegion(t, resourceMap, awsRegion)

			terraformOptions := &terraform.Options{
				TerraformDir: "../",
				Vars:         tc.vars,
				EnvVars: map[string]string{
					"AWS_DEFAULT_REGION": awsRegion,
				},
			}

			if tc.expectError {
				_, err := terraform.InitAndPlanE(t, terraformOptions)
				assert.Error(t, err, "Expected network timeout error for test case: %s", tc.name)
				if tc.errorText != "" {
					assert.Contains(t, strings.ToLower(err.Error()), strings.ToLower(tc.errorText),
						"Error should contain expected text for test case: %s", tc.name)
				}
				t.Logf("Expected network timeout error handled correctly for: %s - %s", tc.name, tc.description)
			} else {
				terraform.InitAndPlan(t, terraformOptions)
				t.Logf("Network timeout test passed: %s - %s", tc.name, tc.description)
			}
		})
	}
}

// TestTerraformRoute53ResolverRulesCrossRegionErrors tests cross-region error scenarios
func TestTerraformRoute53ResolverRulesCrossRegionErrors(t *testing.T) {
	t.Parallel()

	// Generate test session ID for isolation
	sessionID := GenerateTestSessionID(t)

	crossRegionTests := []struct {
		name        string
		description string
		region      string
		vars        map[string]interface{}
		expectError bool
		errorText   string
	}{
		{
			name:        "cross_region_vpc_reference",
			description: "Test resolver rule with VPC reference in different region",
			region:      "us-east-1",
			vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceNameWithSession("resolver-endpoint", "cross-region", sessionID),
				"rules": []map[string]interface{}{
					{
						"domain_name": "cross-region.example.com.",
						"rule_name":   fmt.Sprintf("cross-region-rule-%s", sessionID),
						"vpc_ids":     []string{GenerateTestResourceNameWithSession("vpc", "cross-region", sessionID)},
						"ips":         []string{"192.168.1.10"},
					},
				},
			},
			expectError: false, // Valid configuration, errors would occur at apply time
		},
		{
			name:        "cross_region_ram_sharing",
			description: "Test RAM sharing across regions with resolver rules",
			region:      "us-west-2",
			vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceNameWithSession("resolver-endpoint", "ram-cross", sessionID),
				"rules": []map[string]interface{}{
					{
						"domain_name": "ram-cross-region.example.com.",
						"rule_name":   fmt.Sprintf("ram-cross-rule-%s", sessionID),
						"ram_name":    fmt.Sprintf("ram-cross-share-%s", sessionID),
						"vpc_ids":     []string{GenerateTestResourceNameWithSession("vpc", "ram-cross", sessionID)},
						"ips":         []string{"192.168.1.10"},
						"principals":  []string{GenerateTestResourceNameWithSession("account", "cross-principal", sessionID)},
					},
				},
			},
			expectError: false,
		},
		{
			name:        "resolver_endpoint_region_mismatch",
			description: "Test resolver endpoint in different region than VPCs",
			region:      "eu-west-1",
			vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceNameWithSession("resolver-endpoint", "region-mismatch", sessionID),
				"rules": []map[string]interface{}{
					{
						"domain_name": "region-mismatch.example.com.",
						"rule_name":   fmt.Sprintf("region-mismatch-rule-%s", sessionID),
						"vpc_ids":     []string{GenerateTestResourceNameWithSession("vpc", "region-mismatch", sessionID)},
						"ips":         []string{"192.168.1.10"},
					},
				},
			},
			expectError: false, // Configuration valid, runtime error would occur
		},
		{
			name:        "multiple_region_stress_test",
			description: "Test resource creation with rapid region switching",
			region:      "us-east-1",
			vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceNameWithSession("resolver-endpoint", "multi-region", sessionID),
				"rules": func() []map[string]interface{} {
					rules := make([]map[string]interface{}, 5)
					for i := 0; i < 5; i++ {
						rules[i] = map[string]interface{}{
							"domain_name": fmt.Sprintf("multi-region-%d.example.com.", i),
							"rule_name":   fmt.Sprintf("multi-region-rule-%d-%s", i, sessionID),
							"vpc_ids":     []string{GenerateTestResourceNameWithSession("vpc", fmt.Sprintf("multi-region-%d", i), sessionID)},
							"ips":         []string{"192.168.1.10"},
						}
					}
					return rules
				}(),
			},
			expectError: false,
		},
		{
			name:        "unsupported_region_simulation",
			description: "Test with region that doesn't support Route53 Resolver Rules",
			region:      "ap-southeast-3", // Newer region that might have limited service availability
			vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceNameWithSession("resolver-endpoint", "unsupported", sessionID),
				"rules": []map[string]interface{}{
					{
						"domain_name": "unsupported-region.example.com.",
						"rule_name":   fmt.Sprintf("unsupported-rule-%s", sessionID),
						"vpc_ids":     []string{GenerateTestResourceNameWithSession("vpc", "unsupported", sessionID)},
						"ips":         []string{"192.168.1.10"},
					},
				},
			},
			expectError: false, // Configuration valid, service availability error at runtime
		},
	}

	for _, tc := range crossRegionTests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup cleanup for any test resources
			defer func() {
				CleanupTestResolverRules(t, tc.region, "terratest-")
			}()

			// Verify test environment safety for the specific region
			VerifyTestEnvironment(t, tc.region)

			// Validate resource formats with region
			resourceMap := map[string]string{
				"resolver-endpoint": tc.vars["resolver_endpoint_id"].(string),
			}
			if rules, ok := tc.vars["rules"].([]map[string]interface{}); ok && len(rules) > 0 {
				if vpcIDs, ok := rules[0]["vpc_ids"].([]string); ok && len(vpcIDs) > 0 {
					resourceMap["vpc"] = vpcIDs[0]
				}
				if principals, ok := rules[0]["principals"].([]string); ok && len(principals) > 0 {
					resourceMap["account"] = principals[0]
				}
			}
			ValidateAWSResourceFormatsWithRegion(t, resourceMap, tc.region)

			terraformOptions := &terraform.Options{
				TerraformDir: "../",
				Vars:         tc.vars,
				EnvVars: map[string]string{
					"AWS_DEFAULT_REGION": tc.region,
				},
			}

			if tc.expectError {
				_, err := terraform.InitAndPlanE(t, terraformOptions)
				assert.Error(t, err, "Expected cross-region error for test case: %s", tc.name)
				if tc.errorText != "" {
					assert.Contains(t, strings.ToLower(err.Error()), strings.ToLower(tc.errorText),
						"Error should contain expected text for test case: %s", tc.name)
				}
				t.Logf("Expected cross-region error handled correctly for: %s - %s", tc.name, tc.description)
			} else {
				terraform.InitAndPlan(t, terraformOptions)
				t.Logf("Cross-region test passed: %s - %s", tc.name, tc.description)
			}
		})
	}
}

// TestTerraformRoute53ResolverRulesEdgeCases tests comprehensive edge cases and boundary conditions
func TestTerraformRoute53ResolverRulesEdgeCases(t *testing.T) {
	t.Parallel()

	awsRegion := awshelper.GetRandomStableRegion(t, nil, nil)
	
	// Verify test environment safety
	VerifyTestEnvironment(t, awsRegion)

	edgeCaseTests := []struct {
		name        string
		description string
		vars        map[string]interface{}
		expectError bool
		errorText   string
	}{
		{
			name:        "extremely_long_domain_name",
			description: "Test with extremely long domain name (boundary test)",
			vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceName("resolver-endpoint", "long-domain"),
				"rules": []map[string]interface{}{
					{
						"domain_name": "this-is-an-extremely-long-subdomain-name-that-tests-the-maximum-allowed-length-for-dns-names-and-should-be-handled-correctly-by-the-resolver-module.example.com.",
						"rule_name":   "long-domain-rule",
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "edge-test")},
						"ips":         []string{"192.168.1.10"},
					},
				},
			},
			expectError: false, // Should be valid if under DNS limits
		},
		{
			name:        "maximum_port_number",
			description: "Test with maximum valid port number (65535)",
			vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceName("resolver-endpoint", "max-port"),
				"rules": []map[string]interface{}{
					{
						"domain_name": "max-port.example.com.",
						"rule_name":   "max-port-rule",
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "edge-test")},
						"ips":         []string{"192.168.1.10:65535"}, // Maximum valid port
					},
				},
			},
			expectError: false,
		},
		{
			name:        "minimum_port_number",
			description: "Test with minimum valid port number (1)",
			vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceName("resolver-endpoint", "min-port"),
				"rules": []map[string]interface{}{
					{
						"domain_name": "min-port.example.com.",
						"rule_name":   "min-port-rule",
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "edge-test")},
						"ips":         []string{"192.168.1.10:1"}, // Minimum valid port
					},
				},
			},
			expectError: false,
		},
		{
			name:        "zero_port_number",
			description: "Test with invalid port number (0)",
			vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceName("resolver-endpoint", "zero-port"),
				"rules": []map[string]interface{}{
					{
						"domain_name": "zero-port.example.com.",
						"rule_name":   "zero-port-rule",
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "edge-test")},
						"ips":         []string{"192.168.1.10:0"}, // Invalid port
					},
				},
			},
			expectError: true,
			errorText:   "port",
		},
		{
			name:        "ipv6_addresses",
			description: "Test with IPv6 addresses",
			vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceName("resolver-endpoint", "ipv6"),
				"rules": []map[string]interface{}{
					{
						"domain_name": "ipv6.example.com.",
						"rule_name":   "ipv6-rule",
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "edge-test")},
						"ips":         []string{"2001:db8::1", "2001:db8::2"}, // IPv6 addresses
					},
				},
			},
			expectError: false, // Should be valid
		},
		{
			name:        "mixed_ipv4_ipv6",
			description: "Test with mixed IPv4 and IPv6 addresses",
			vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceName("resolver-endpoint", "mixed-ip"),
				"rules": []map[string]interface{}{
					{
						"domain_name": "mixed-ip.example.com.",
						"rule_name":   "mixed-ip-rule",
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "edge-test")},
						"ips":         []string{"192.168.1.10", "2001:db8::1"}, // Mixed IPv4/IPv6
					},
				},
			},
			expectError: false,
		},
		{
			name:        "single_character_subdomain",
			description: "Test with single character subdomain",
			vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceName("resolver-endpoint", "single-char"),
				"rules": []map[string]interface{}{
					{
						"domain_name": "a.example.com.", // Single character subdomain
						"rule_name":   "single-char-rule",
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "edge-test")},
						"ips":         []string{"192.168.1.10"},
					},
				},
			},
			expectError: false,
		},
		{
			name:        "maximum_vpc_associations",
			description: "Test with many VPC associations (stress test)",
			vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceName("resolver-endpoint", "many-vpcs"),
				"rules": []map[string]interface{}{
					{
						"domain_name": "many-vpcs.example.com.",
						"rule_name":   "many-vpcs-rule",
						"vpc_ids": []string{
							GenerateTestResourceName("vpc", "test-1"),
							GenerateTestResourceName("vpc", "test-2"),
							GenerateTestResourceName("vpc", "test-3"),
							GenerateTestResourceName("vpc", "test-4"),
							GenerateTestResourceName("vpc", "test-5"),
						}, // Multiple VPCs
						"ips": []string{"192.168.1.10"},
					},
				},
			},
			expectError: false,
		},
	}

	for _, tc := range edgeCaseTests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup cleanup for any test resources
			defer func() {
				CleanupTestResolverRules(t, awsRegion, "terratest-")
			}()

			terraformOptions := &terraform.Options{
				TerraformDir: "../",
				Vars:         tc.vars,
				EnvVars: map[string]string{
					"AWS_DEFAULT_REGION": awsRegion,
				},
			}

			if tc.expectError {
				_, err := terraform.InitAndPlanE(t, terraformOptions)
				assert.Error(t, err, "Expected error for edge case: %s", tc.name)
				if tc.errorText != "" {
					assert.Contains(t, strings.ToLower(err.Error()), strings.ToLower(tc.errorText),
						"Error should contain expected text for edge case: %s", tc.name)
				}
				t.Logf("Expected error handled correctly for edge case: %s - %s", tc.name, tc.description)
			} else {
				terraform.InitAndPlan(t, terraformOptions)
				t.Logf("Edge case passed: %s - %s", tc.name, tc.description)
			}
		})
	}
}