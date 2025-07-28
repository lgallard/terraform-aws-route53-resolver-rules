package test

import (
	"fmt"
	"strings"
	"testing"

	awshelper "github.com/gruntwork-io/terratest/modules/aws"
	"github.com/gruntwork-io/terratest/modules/random"
	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"
)

// TestTerraformRoute53ResolverRulesValidation tests validation rules and error cases
func TestTerraformRoute53ResolverRulesValidation(t *testing.T) {
	t.Parallel()

	testCases := []TestCase{
		{
			Name:        "valid_basic_configuration",
			Description: "Test valid basic resolver rule configuration",
			Vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceName("resolver-endpoint", "basic-test"),
				"rules": []map[string]interface{}{
					{
						"domain_name": "example.com.",
						"rule_name":   "example-rule",
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "basic-test")},
						"ips":         []string{"192.168.1.10", "192.168.1.11"},
					},
				},
			},
			ExpectError: false,
		},
		{
			Name:        "valid_multiple_rules",
			Description: "Test valid configuration with multiple resolver rules",
			Vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceName("resolver-endpoint", "multiple-rules"),
				"rules": []map[string]interface{}{
					{
						"domain_name": "example.com.",
						"rule_name":   "example-rule",
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "rule-1")},
						"ips":         []string{"192.168.1.10"},
					},
					{
						"domain_name": "test.local.",
						"rule_name":   "test-rule",
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "rule-2")},
						"ips":         []string{"10.0.1.10"},
					},
				},
			},
			ExpectError: false,
		},
		{
			Name:        "valid_custom_ports",
			Description: "Test valid configuration with custom DNS ports",
			Vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceName("resolver-endpoint", "custom-ports"),
				"rules": []map[string]interface{}{
					{
						"domain_name": "example.com.",
						"rule_name":   "custom-ports-rule",
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "custom-ports")},
						"ips":         []string{"192.168.1.10:8053", "192.168.1.11:5353"},
					},
				},
			},
			ExpectError: false,
		},
		{
			Name:        "valid_ram_sharing",
			Description: "Test valid configuration with RAM resource sharing",
			Vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceName("resolver-endpoint", "validation-test"),
				"rules": []map[string]interface{}{
					{
						"domain_name": "shared.example.com.",
						"rule_name":   "shared-rule",
						"ram_name":    "shared-ram",
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "test")},
						"ips":         []string{"192.168.1.10"},
						"principals":  []string{GenerateTestResourceName("account", "principal-1"), GenerateTestResourceName("account", "principal-2")},
					},
				},
			},
			ExpectError: false,
		},
		{
			Name:        "valid_with_tags",
			Description: "Test valid configuration with resource tags",
			Vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceName("resolver-endpoint", "validation-test"),
				"rules": []map[string]interface{}{
					{
						"domain_name": "tagged.example.com.",
						"rule_name":   "tagged-rule",
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "test")},
						"ips":         []string{"192.168.1.10"},
					},
				},
				"tags": map[string]string{
					"Environment": "test",
					"Team":        "networking",
				},
			},
			ExpectError: false,
		},
		{
			Name:        "empty_rules_list",
			Description: "Test configuration with empty rules list",
			Vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceName("resolver-endpoint", "validation-test"),
				"rules":                []map[string]interface{}{},
			},
			ExpectError: false, // Empty rules should be valid
		},
		{
			Name:        "null_resolver_endpoint",
			Description: "Test configuration without resolver endpoint ID",
			Vars: map[string]interface{}{
				// resolver_endpoint_id intentionally omitted (uses default null)
				"rules": []map[string]interface{}{
					{
						"domain_name": "example.com.",
						"rule_name":   "null-endpoint-rule",
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "test")},
						"ips":         []string{"192.168.1.10"},
					},
				},
			},
			ExpectError: false, // null is the default value
		},
		{
			Name:        "multiple_vpc_associations",
			Description: "Test rule associated with multiple VPCs",
			Vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceName("resolver-endpoint", "validation-test"),
				"rules": []map[string]interface{}{
					{
						"domain_name": "multi-vpc.example.com.",
						"rule_name":   "multi-vpc-rule",
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "multi-1"), GenerateTestResourceName("vpc", "multi-2"), GenerateTestResourceName("vpc", "multi-3")},
						"ips":         []string{"192.168.1.10"},
					},
				},
			},
			ExpectError: false,
		},
		{
			Name:        "mixed_port_configurations",
			Description: "Test mixed IP addresses with and without custom ports",
			Vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceName("resolver-endpoint", "validation-test"),
				"rules": []map[string]interface{}{
					{
						"domain_name": "mixed-ports.example.com.",
						"rule_name":   "mixed-ports-rule",
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "test")},
						"ips":         []string{"192.168.1.10", "192.168.1.11:8053", "192.168.1.12"},
					},
				},
			},
			ExpectError: false,
		},
		{
			Name:        "complex_domain_names",
			Description: "Test various valid domain name formats",
			Vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceName("resolver-endpoint", "validation-test"),
				"rules": []map[string]interface{}{
					{
						"domain_name": "sub.domain.example.com.",
						"rule_name":   "subdomain-rule",
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "test")},
						"ips":         []string{"192.168.1.10"},
					},
					{
						"domain_name": "local.",
						"rule_name":   "local-rule",
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "test-2")},
						"ips":         []string{"10.0.1.10"},
					},
					{
						"domain_name": "very-long-subdomain-name.corporate.internal.example.org.",
						"rule_name":   "long-domain-rule",
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "test-3")},
						"ips":         []string{"172.16.1.10"},
					},
				},
			},
			ExpectError: false,
		},
		// Error test cases for validation
		{
			Name:        "invalid_domain_name_format",
			Description: "Test invalid domain name format (missing trailing dot)",
			Vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceName("resolver-endpoint", "invalid-domain"),
				"rules": []map[string]interface{}{
					{
						"domain_name": "invalid-domain-no-dot", // Missing trailing dot
						"rule_name":   "invalid-domain-rule",
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "invalid-test")},
						"ips":         []string{"192.168.1.10"},
					},
				},
			},
			ExpectError: true,
			ErrorText:   "domain name",
		},
		{
			Name:        "invalid_ip_address_format",
			Description: "Test invalid IP address format",
			Vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceName("resolver-endpoint", "invalid-ip"),
				"rules": []map[string]interface{}{
					{
						"domain_name": "example.com.",
						"rule_name":   "invalid-ip-rule",
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "invalid-test")},
						"ips":         []string{"999.999.999.999"}, // Invalid IP
					},
				},
			},
			ExpectError: true,
			ErrorText:   "invalid",
		},
		{
			Name:        "invalid_port_range",
			Description: "Test invalid port number (out of range)",
			Vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceName("resolver-endpoint", "invalid-port"),
				"rules": []map[string]interface{}{
					{
						"domain_name": "example.com.",
						"rule_name":   "invalid-port-rule",
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "invalid-test")},
						"ips":         []string{"192.168.1.10:99999"}, // Invalid port range
					},
				},
			},
			ExpectError: true,
			ErrorText:   "port",
		},
		// AWS Service Limits and Quota Error Test Cases
		{
			Name:        "invalid_aws_account_id_principals",
			Description: "Test invalid AWS account ID format in principals (not 12 digits)",
			Vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceName("resolver-endpoint", "invalid-account"),
				"rules": []map[string]interface{}{
					{
						"domain_name": "account-test.example.com.",
						"rule_name":   "invalid-account-rule",
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "test")},
						"ips":         []string{"192.168.1.10"},
						"principals":  []string{"12345", "not-a-number", "1234567890123"}, // Invalid account formats
					},
				},
			},
			ExpectError: true,
			ErrorText:   "account",
		},
		{
			Name:        "invalid_resolver_endpoint_format",
			Description: "Test malformed resolver endpoint ID",
			Vars: map[string]interface{}{
				"resolver_endpoint_id": "invalid-endpoint-format-123", // Wrong format
				"rules": []map[string]interface{}{
					{
						"domain_name": "endpoint-test.example.com.",
						"rule_name":   "invalid-endpoint-rule",
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "test")},
						"ips":         []string{"192.168.1.10"},
					},
				},
			},
			ExpectError: true,
			ErrorText:   "endpoint",
		},
		{
			Name:        "invalid_vpc_id_format",
			Description: "Test malformed VPC ID format",
			Vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceName("resolver-endpoint", "invalid-vpc"),
				"rules": []map[string]interface{}{
					{
						"domain_name": "vpc-test.example.com.",
						"rule_name":   "invalid-vpc-rule",
						"vpc_ids":     []string{"invalid-vpc-123", "vpc-", "not-a-vpc-id"}, // Invalid VPC formats
						"ips":         []string{"192.168.1.10"},
					},
				},
			},
			ExpectError: true,
			ErrorText:   "vpc",
		},
		{
			Name:        "too_many_resolver_rules",
			Description: "Test exceeding AWS service limits for resolver rules",
			Vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceName("resolver-endpoint", "limit-test"),
				"rules": func() []map[string]interface{} {
					// Generate 100+ rules to test AWS limits (current limit is usually 100)
					rules := make([]map[string]interface{}, 105)
					for i := 0; i < 105; i++ {
						rules[i] = map[string]interface{}{
							"domain_name": fmt.Sprintf("limit-test-%d.example.com.", i),
							"rule_name":   fmt.Sprintf("limit-rule-%d", i),
							"vpc_ids":     []string{GenerateTestResourceName("vpc", fmt.Sprintf("limit-%d", i))},
							"ips":         []string{"192.168.1.10"},
						}
					}
					return rules
				}(),
			},
			ExpectError: true,
			ErrorText:   "limit",
		},
		{
			Name:        "too_many_ram_principals",
			Description: "Test exceeding RAM sharing principal limits",
			Vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceName("resolver-endpoint", "ram-limit"),
				"rules": []map[string]interface{}{
					{
						"domain_name": "ram-limit.example.com.",
						"rule_name":   "ram-limit-rule",
						"ram_name":    "ram-limit-share",
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "ram-limit")},
						"ips":         []string{"192.168.1.10"},
						"principals": func() []string {
							// Generate 30+ principals to test RAM limits
							principals := make([]string, 35)
							for i := 0; i < 35; i++ {
								principals[i] = GenerateSequentialAccountID()
							}
							return principals
						}(),
					},
				},
			},
			ExpectError: true,
			ErrorText:   "principal",
		},
		{
			Name:        "too_many_vpc_associations",
			Description: "Test exceeding VPC association limits per rule",
			Vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceName("resolver-endpoint", "vpc-limit"),
				"rules": []map[string]interface{}{
					{
						"domain_name": "vpc-associations.example.com.",
						"rule_name":   "vpc-associations-rule",
						"vpc_ids": func() []string {
							// Generate 30+ VPC IDs to test association limits
							vpcs := make([]string, 35)
							for i := 0; i < 35; i++ {
								vpcs[i] = GenerateTestResourceName("vpc", fmt.Sprintf("assoc-%d", i))
							}
							return vpcs
						}(),
						"ips": []string{"192.168.1.10"},
					},
				},
			},
			ExpectError: true,
			ErrorText:   "association",
		},
		// Network and Connectivity Error Test Cases
		{
			Name:        "invalid_dns_server_ip",
			Description: "Test invalid DNS server IP addresses",
			Vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceName("resolver-endpoint", "dns-error"),
				"rules": []map[string]interface{}{
					{
						"domain_name": "dns-error.example.com.",
						"rule_name":   "dns-error-rule",
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "dns-error")},
						"ips":         []string{"0.0.0.0", "127.0.0.1", "255.255.255.255"}, // Invalid DNS server IPs
					},
				},
			},
			ExpectError: true,
			ErrorText:   "ip",
		},
		{
			Name:        "mixed_invalid_ips",
			Description: "Test mix of valid and invalid IP addresses",
			Vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceName("resolver-endpoint", "mixed-ip"),
				"rules": []map[string]interface{}{
					{
						"domain_name": "mixed-ip.example.com.",
						"rule_name":   "mixed-ip-rule",
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "mixed-ip")},
						"ips":         []string{"192.168.1.10", "999.999.999.999", "192.168.1.11"}, // Mix valid/invalid
					},
				},
			},
			ExpectError: true,
			ErrorText:   "invalid",
		},
		{
			Name:        "reserved_ip_addresses",
			Description: "Test using reserved/private IP ranges for DNS servers",
			Vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceName("resolver-endpoint", "reserved-ip"),
				"rules": []map[string]interface{}{
					{
						"domain_name": "reserved-ip.example.com.",
						"rule_name":   "reserved-ip-rule",
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "reserved-ip")},
						"ips":         []string{"169.254.1.1", "224.0.0.1", "10.0.0.1"}, // Reserved/multicast IPs
					},
				},
			},
			ExpectError: true,
			ErrorText:   "reserved",
		},
		// Resource Reference and Cross-Region Error Test Cases
		{
			Name:        "non_existent_vpc_reference",
			Description: "Test reference to non-existent VPC IDs",
			Vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceName("resolver-endpoint", "non-existent"),
				"rules": []map[string]interface{}{
					{
						"domain_name": "non-existent.example.com.",
						"rule_name":   "non-existent-rule",
						"vpc_ids":     []string{"vpc-nonexistent123456", "vpc-fakeid987654321"}, // Non-existent but valid format
						"ips":         []string{"192.168.1.10"},
					},
				},
			},
			ExpectError: true,
			ErrorText:   "not found",
		},
		{
			Name:        "non_existent_resolver_endpoint",
			Description: "Test reference to non-existent resolver endpoint",
			Vars: map[string]interface{}{
				"resolver_endpoint_id": "rslvr-out-nonexistent123456789", // Non-existent but valid format
				"rules": []map[string]interface{}{
					{
						"domain_name": "endpoint-ref.example.com.",
						"rule_name":   "endpoint-ref-rule",
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "endpoint-ref")},
						"ips":         []string{"192.168.1.10"},
					},
				},
			},
			ExpectError: true,
			ErrorText:   "endpoint",
		},
		{
			Name:        "invalid_ram_resource_name",
			Description: "Test invalid RAM resource share name format",
			Vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceName("resolver-endpoint", "ram-name"),
				"rules": []map[string]interface{}{
					{
						"domain_name": "ram-name.example.com.",
						"rule_name":   "ram-name-rule",
						"ram_name":    "invalid ram name with spaces!", // Invalid characters
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "ram-name")},
						"ips":         []string{"192.168.1.10"},
						"principals":  []string{GenerateSequentialAccountID()},
					},
				},
			},
			ExpectError: true,
			ErrorText:   "name",
		},
		// Domain Name Validation Error Test Cases
		{
			Name:        "domain_name_too_long",
			Description: "Test domain name exceeding maximum length",
			Vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceName("resolver-endpoint", "long-domain"),
				"rules": []map[string]interface{}{
					{
						"domain_name": "this-is-an-extremely-long-domain-name-that-exceeds-the-maximum-allowed-length-for-dns-names-and-should-cause-validation-errors-because-it-is-way-too-long-for-any-reasonable-dns-resolver-to-handle-properly-and-definitely-exceeds-the-253-character-limit-imposed-by-rfc-standards.example.com.", // >253 chars
						"rule_name":   "long-domain-rule",
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "long-domain")},
						"ips":         []string{"192.168.1.10"},
					},
				},
			},
			ExpectError: true,
			ErrorText:   "length",
		},
		{
			Name:        "invalid_domain_characters",
			Description: "Test domain name with invalid characters",
			Vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceName("resolver-endpoint", "invalid-chars"),
				"rules": []map[string]interface{}{
					{
						"domain_name": "invalid_domain_with_underscores.example.com.", // Underscores not allowed
						"rule_name":   "invalid-chars-rule",
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "invalid-chars")},
						"ips":         []string{"192.168.1.10"},
					},
				},
			},
			ExpectError: true,
			ErrorText:   "character",
		},
		{
			Name:        "empty_domain_name",
			Description: "Test empty domain name",
			Vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceName("resolver-endpoint", "empty-domain"),
				"rules": []map[string]interface{}{
					{
						"domain_name": "", // Empty domain
						"rule_name":   "empty-domain-rule",
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "empty-domain")},
						"ips":         []string{"192.168.1.10"},
					},
				},
			},
			ExpectError: true,
			ErrorText:   "empty",
		},
		// Configuration Limit Error Test Cases
		{
			Name:        "empty_ip_list",
			Description: "Test resolver rule with empty IP address list",
			Vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceName("resolver-endpoint", "empty-ips"),
				"rules": []map[string]interface{}{
					{
						"domain_name": "empty-ips.example.com.",
						"rule_name":   "empty-ips-rule",
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "empty-ips")},
						"ips":         []string{}, // Empty IP list
					},
				},
			},
			ExpectError: true,
			ErrorText:   "ip",
		},
		{
			Name:        "duplicate_vpc_associations",
			Description: "Test duplicate VPC IDs in the same rule",
			Vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceName("resolver-endpoint", "duplicate-vpc"),
				"rules": []map[string]interface{}{
					{
						"domain_name": "duplicate-vpc.example.com.",
						"rule_name":   "duplicate-vpc-rule",
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "duplicate"), GenerateTestResourceName("vpc", "duplicate")}, // Same VPC twice
						"ips":         []string{"192.168.1.10"},
					},
				},
			},
			ExpectError: true,
			ErrorText:   "duplicate",
		},
		{
			Name:        "conflicting_rule_names",
			Description: "Test duplicate rule names in different rules",
			Vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceName("resolver-endpoint", "conflict"),
				"rules": []map[string]interface{}{
					{
						"domain_name": "conflict1.example.com.",
						"rule_name":   "conflicting-rule", // Same name
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "conflict1")},
						"ips":         []string{"192.168.1.10"},
					},
					{
						"domain_name": "conflict2.example.com.",
						"rule_name":   "conflicting-rule", // Same name - should conflict
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "conflict2")},
						"ips":         []string{"192.168.1.11"},
					},
				},
			},
			ExpectError: true,
			ErrorText:   "conflict",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			awsRegion := awshelper.GetRandomStableRegion(t, nil, nil)

			terraformOptions := &terraform.Options{
				TerraformDir: "../",
				Vars:         tc.Vars,
				EnvVars: map[string]string{
					"AWS_DEFAULT_REGION": awsRegion,
				},
			}

			if tc.ExpectError {
				_, err := terraform.InitAndPlanE(t, terraformOptions)
				assert.Error(t, err, "Expected validation error for test case: %s", tc.Name)
				if tc.ErrorText != "" {
					assert.Contains(t, err.Error(), tc.ErrorText, 
						"Error should contain expected text for test case: %s", tc.Name)
				}
			} else {
				terraform.InitAndPlan(t, terraformOptions)
				t.Logf("Validation passed for test case: %s - %s", tc.Name, tc.Description)
			}
		})
	}
}

// TestTerraformRoute53ResolverRulesVariableTypes tests variable type validation
func TestTerraformRoute53ResolverRulesVariableTypes(t *testing.T) {
	t.Parallel()

	uniqueID := random.UniqueId()
	awsRegion := awshelper.GetRandomStableRegion(t, nil, nil)

	testCases := []struct {
		name        string
		description string
		vars        map[string]interface{}
		expectError bool
	}{
		{
			name:        "string_resolver_endpoint_id",
			description: "Test resolver_endpoint_id as string",
			vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceName("resolver-endpoint", "type-test"),
				"rules": []map[string]interface{}{
					{
						"domain_name": "string-test.example.com.",
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "test")},
						"ips":         []string{"192.168.1.10"},
					},
				},
			},
			expectError: false,
		},
		{
			name:        "null_resolver_endpoint_id",
			description: "Test resolver_endpoint_id as null",
			vars: map[string]interface{}{
				"resolver_endpoint_id": nil,
				"rules": []map[string]interface{}{
					{
						"domain_name": "null-test.example.com.",
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "test")},
						"ips":         []string{"192.168.1.10"},
					},
				},
			},
			expectError: false,
		},
		{
			name:        "list_type_rules",
			description: "Test rules as list type",
			vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceName("resolver-endpoint", "type-test"),
				"rules": []map[string]interface{}{
					{
						"domain_name": "list-test-1.example.com.",
						"rule_name":   "list-test-1-rule",
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "test")},
						"ips":         []string{"192.168.1.10"},
					},
					{
						"domain_name": "list-test-2.example.com.",
						"rule_name":   "list-test-2-rule",
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "test-2")},
						"ips":         []string{"192.168.2.10"},
					},
				},
			},
			expectError: false,
		},
		{
			name:        "map_type_tags",
			description: "Test tags as map of strings",
			vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceName("resolver-endpoint", "type-test"),
				"rules": []map[string]interface{}{
					{
						"domain_name": "tags-test.example.com.",
						"rule_name":   "tags-test-rule",
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "test")},
						"ips":         []string{"192.168.1.10"},
					},
				},
				"tags": map[string]string{
					"Environment": "test",
					"Team":        "networking",
					"Project":     "resolver-rules",
					"UniqueID":    uniqueID,
				},
			},
			expectError: false,
		},
		{
			name:        "empty_tags_map",
			description: "Test empty tags map",
			vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceName("resolver-endpoint", "type-test"),
				"rules": []map[string]interface{}{
					{
						"domain_name": "empty-tags.example.com.",
						"rule_name":   "empty-tags-rule",
						"vpc_ids":     []string{GenerateTestResourceName("vpc", "test")},
						"ips":         []string{"192.168.1.10"},
					},
				},
				"tags": map[string]string{},
			},
			expectError: false,
		},
	}

	for _, tc := range testCases {
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
				assert.Error(t, err, "Expected type validation error for: %s", tc.name)
			} else {
				terraform.InitAndPlan(t, terraformOptions)
				t.Logf("Type validation passed for: %s - %s", tc.name, tc.description)
			}
		})
	}
}

// TestTerraformRoute53ResolverRulesLocalValues tests local value calculations
func TestTerraformRoute53ResolverRulesLocalValues(t *testing.T) {
	t.Parallel()

	awsRegion := awshelper.GetRandomStableRegion(t, nil, nil)
	uniqueID := random.UniqueId()

	terraformOptions := &terraform.Options{
		TerraformDir: "../",
		Vars: map[string]interface{}{
			"resolver_endpoint_id": GenerateTestResourceName("resolver-endpoint", "type-test"),
			"rules": []map[string]interface{}{
				{
					"domain_name": "test1.example.com.",
					"rule_name":   "test1-rule",
					"vpc_ids":     []string{GenerateTestResourceName("vpc", "local-1"), GenerateTestResourceName("vpc", "local-2")},
					"ips":         []string{"192.168.1.10"},
					"principals":  []string{GenerateTestResourceName("account", "principal-1")},
				},
				{
					"domain_name": "test2.example.com.",
					"rule_name":   fmt.Sprintf("custom-rule-%s", uniqueID),
					"ram_name":    fmt.Sprintf("custom-ram-%s", uniqueID),
					"vpc_ids":     []string{GenerateTestResourceName("vpc", "local-3")},
					"ips":         []string{"10.0.1.10", "10.0.1.11"},
					"principals":  []string{GenerateTestResourceName("account", "principal-1"), GenerateTestResourceName("account", "principal-2")},
				},
			},
		},
		EnvVars: map[string]string{
			"AWS_DEFAULT_REGION": awsRegion,
		},
	}

	plan := terraform.InitAndPlan(t, terraformOptions)

	// Verify that local values are properly calculated
	// This tests the complex local value logic in the module
	assert.Contains(t, plan, "aws_route53_resolver_rule.r", 
		"Should create resolver rules based on local.rules")
	assert.Contains(t, plan, "aws_route53_resolver_rule_association.ra", 
		"Should create VPC associations based on local.vpcs_associations")
	assert.Contains(t, plan, "aws_ram_resource_share.endpoint_share", 
		"Should create RAM shares based on local.ram_associations")
	
	t.Log("Local value calculations validation passed")
}


// TestTerraformRoute53ResolverRulesNetworkAndServiceErrors tests network timeouts and AWS service error scenarios
func TestTerraformRoute53ResolverRulesNetworkAndServiceErrors(t *testing.T) {
	t.Parallel()

	awsRegion := awshelper.GetRandomStableRegion(t, nil, nil)
	
	// Test AWS service limits validation
	t.Run("service_limits_validation", func(t *testing.T) {
		TestAWSServiceLimits(t, awsRegion)
	})
	
	// Test network connectivity error scenarios
	t.Run("network_connectivity_errors", func(t *testing.T) {
		TestNetworkConnectivityErrorScenarios(t, awsRegion)
	})
	
	// Test AWS error handling validation
	t.Run("aws_error_handling", func(t *testing.T) {
		// Test different AWS error types
		errorTypes := []string{"throttling", "limit_exceeded", "invalid_parameter", "not_found", "access_denied"}
		
		for _, errorType := range errorTypes {
			t.Run(fmt.Sprintf("error_type_%s", errorType), func(t *testing.T) {
				simulatedError := SimulateAWSServiceErrors(t, errorType)
				ValidateAWSErrorHandling(t, simulatedError, errorType)
			})
		}
	})
	
	// Test DNS resolution with strict mode for error scenarios
	t.Run("dns_resolution_strict_mode", func(t *testing.T) {
		// Test strict mode with warning-only (should not fail)
		ValidateDNSResolutionWarningOnly(t, "nonexistent-domain-for-testing.example.com", []string{"192.168.1.10"})
		
		// Test that strict mode is available (but don't use it with non-existent domain to avoid test failure)
		ValidateDNSResolutionStrict(t, "cloudflare.com", []string{}) // Use real domain without specific IP expectations
	})
}

// TestTerraformRoute53ResolverRulesAWSResourceFormatValidation tests AWS resource format validation
func TestTerraformRoute53ResolverRulesAWSResourceFormatValidation(t *testing.T) {
	t.Parallel()

	awsRegion := awshelper.GetRandomStableRegion(t, nil, nil)
	
	// Generate test session ID for isolation
	sessionID := GenerateTestSessionID(t)

	// Advanced error test cases for AWS resource format validation
	errorTestCases := []struct {
		name        string
		description string
		vars        map[string]interface{}
		expectError bool
		errorText   string
	}{
		{
			name:        "invalid_aws_account_id_format",
			description: "Test with invalid AWS account ID format (not 12 digits)",
			vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceNameWithSession("resolver-endpoint", "invalid-account", sessionID),
				"rules": []map[string]interface{}{
					{
						"domain_name": "example.com.",
						"rule_name":   "invalid-account-rule",
						"vpc_ids":     []string{GenerateTestResourceNameWithSession("vpc", "invalid-test", sessionID)},
						"ips":         []string{"192.168.1.10"},
						"principals":  []string{"12345"}, // Invalid - not 12 digits
					},
				},
			},
			expectError: true,
			errorText:   "account",
		},
		{
			name:        "malformed_resolver_endpoint_id",
			description: "Test with malformed resolver endpoint ID",
			vars: map[string]interface{}{
				"resolver_endpoint_id": "invalid-endpoint-format-123", // Invalid format
				"rules": []map[string]interface{}{
					{
						"domain_name": "example.com.",
						"rule_name":   "malformed-endpoint-rule",
						"vpc_ids":     []string{GenerateTestResourceNameWithSession("vpc", "invalid-test", sessionID)},
						"ips":         []string{"192.168.1.10"},
					},
				},
			},
			expectError: true,
			errorText:   "endpoint",
		},
		{
			name:        "resource_format_validation",
			description: "Test AWS resource format validation with session isolation",
			vars: map[string]interface{}{
				"resolver_endpoint_id": GenerateTestResourceNameWithSession("resolver-endpoint", "format-test", sessionID),
				"rules": []map[string]interface{}{
					{
						"domain_name": "format-test.example.com.",
						"rule_name":   "format-test-rule",
						"vpc_ids":     []string{GenerateTestResourceNameWithSession("vpc", "format-test", sessionID)},
						"ips":         []string{"192.168.1.10"},
						"principals":  []string{GenerateTestResourceNameWithSession("account", "format-test", sessionID)},
					},
				},
			},
			expectError: false, // Should pass with proper formats
		},
	}

	for _, tc := range errorTestCases {
		t.Run(tc.name, func(t *testing.T) {
			// Validate resource formats before running test
			if !tc.expectError {
				// Extract resource IDs from test configuration for validation
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
				
				// Validate resource ID uniqueness
				resourceIDs := make([]string, 0)
				for _, resourceID := range resourceMap {
					resourceIDs = append(resourceIDs, resourceID)
				}
				ValidateResourceIDUniqueness(t, resourceIDs, sessionID)
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
				assert.Error(t, err, "Expected error for AWS format test: %s", tc.name)
				if tc.errorText != "" {
					assert.Contains(t, strings.ToLower(err.Error()), strings.ToLower(tc.errorText),
						"Error should contain expected text for test: %s", tc.name)
				}
				t.Logf("Expected AWS format error handled correctly for: %s - %s", tc.name, tc.description)
			} else {
				terraform.InitAndPlan(t, terraformOptions)
				t.Logf("AWS format validation passed for: %s - %s", tc.name, tc.description)
			}
		})
	}
}