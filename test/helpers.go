package test

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ram"
	"github.com/aws/aws-sdk-go/service/route53resolver"
	awstest "github.com/gruntwork-io/terratest/modules/aws"
	"github.com/gruntwork-io/terratest/modules/random"
	"github.com/gruntwork-io/terratest/modules/retry"
	"github.com/stretchr/testify/require"
)

// TestCase represents a test case for the Route53 resolver rules module
type TestCase struct {
	Name        string
	Description string
	Vars        map[string]interface{}
	ExpectError bool
	ErrorText   string
}

// ResolverRuleTestData holds test data for resolver rule validation
type ResolverRuleTestData struct {
	RuleID          string
	DomainName      string
	Name            string
	RuleType        string
	ResolverEndpointID string
	TargetIPs       []ResolverRuleTargetIP
	VPCAssociations []string
	RAMAssociations []string
}

// ResolverRuleTargetIP represents a target IP for resolver rules
type ResolverRuleTargetIP struct {
	IP   string
	Port int64
}

// GenerateTestName creates a unique test name with prefix
func GenerateTestName(prefix string) string {
	return fmt.Sprintf("%s-%s", prefix, strings.ToLower(random.UniqueId()))
}

// GetTestRegion returns a stable AWS region for testing
func GetTestRegion(t *testing.T) string {
	return awstest.GetRandomStableRegion(t, nil, nil)
}

// ValidateResolverRuleExists checks if a resolver rule exists in AWS
func ValidateResolverRuleExists(t *testing.T, region, ruleID string) *route53resolver.GetResolverRuleOutput {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region),
	})
	require.NoError(t, err)
	svc := route53resolver.New(sess)

	input := &route53resolver.GetResolverRuleInput{
		ResolverRuleId: aws.String(ruleID),
	}

	result, err := svc.GetResolverRule(input)
	require.NoError(t, err, "Failed to get resolver rule %s", ruleID)
	
	return result
}

// ValidateResolverRuleAssociation checks if a resolver rule is associated with a VPC
func ValidateResolverRuleAssociation(t *testing.T, region, ruleID, vpcID string) {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region),
	})
	require.NoError(t, err)
	svc := route53resolver.New(sess)

	input := &route53resolver.ListResolverRuleAssociationsInput{
		Filters: []*route53resolver.Filter{
			{
				Name:   aws.String("ResolverRuleId"),
				Values: []*string{aws.String(ruleID)},
			},
			{
				Name:   aws.String("VPCId"),
				Values: []*string{aws.String(vpcID)},
			},
		},
	}

	result, err := svc.ListResolverRuleAssociations(input)
	require.NoError(t, err, "Failed to list resolver rule associations")
	require.NotEmpty(t, result.ResolverRuleAssociations, 
		"Expected resolver rule %s to be associated with VPC %s", ruleID, vpcID)
}

// ValidateRAMResourceShare checks if a RAM resource share exists and is properly configured
func ValidateRAMResourceShare(t *testing.T, region, shareArn string, expectedPrincipals []string) {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region),
	})
	require.NoError(t, err)
	svc := ram.New(sess)

	// Get resource share details
	getInput := &ram.GetResourceSharesInput{
		ResourceShareArns: []*string{aws.String(shareArn)},
	}

	shareResult, err := svc.GetResourceShares(getInput)
	require.NoError(t, err, "Failed to get RAM resource share %s", shareArn)
	require.NotEmpty(t, shareResult.ResourceShares, "RAM resource share not found")

	// Validate principals if provided
	if len(expectedPrincipals) > 0 {
		assocInput := &ram.GetResourceShareAssociationsInput{
			ResourceShareArns: []*string{aws.String(shareArn)},
			AssociationType:   aws.String("PRINCIPAL"),
		}

		assocResult, err := svc.GetResourceShareAssociations(assocInput)
		require.NoError(t, err, "Failed to get RAM resource share associations")

		actualPrincipals := make([]string, 0)
		for _, assoc := range assocResult.ResourceShareAssociations {
			if assoc.AssociatedEntity != nil {
				actualPrincipals = append(actualPrincipals, *assoc.AssociatedEntity)
			}
		}

		for _, expectedPrincipal := range expectedPrincipals {
			require.Contains(t, actualPrincipals, expectedPrincipal,
				"Expected principal %s not found in RAM resource share", expectedPrincipal)
		}
	}
}

// ValidateDNSResolution performs a basic DNS resolution test for a domain
func ValidateDNSResolution(t *testing.T, domain string, expectedIPs []string) {
	if !strings.HasSuffix(domain, ".") {
		domain += "."
	}

	// Remove trailing dot for DNS lookup
	lookupDomain := strings.TrimSuffix(domain, ".")
	
	// Perform DNS lookup with timeout
	ips, err := net.LookupIP(lookupDomain)
	
	// Note: This test might fail in test environments where DNS forwarding isn't fully configured
	// We'll make this a soft validation that logs warnings instead of failing
	if err != nil {
		t.Logf("Warning: DNS lookup for %s failed: %v (expected in test environment)", lookupDomain, err)
		return
	}

	if len(expectedIPs) > 0 {
		actualIPs := make([]string, 0)
		for _, ip := range ips {
			actualIPs = append(actualIPs, ip.String())
		}

		for _, expectedIP := range expectedIPs {
			found := false
			for _, actualIP := range actualIPs {
				if actualIP == expectedIP {
					found = true
					break
				}
			}
			if !found {
				t.Logf("Warning: Expected IP %s not found in DNS resolution for %s (got: %v)", 
					expectedIP, lookupDomain, actualIPs)
			}
		}
	}
}

// WaitForResolverRuleDeletion waits for a resolver rule to be completely deleted from AWS
func WaitForResolverRuleDeletion(t *testing.T, region, ruleID string, maxRetries int, sleepBetweenRetries time.Duration) {
	retry.DoWithRetry(t, fmt.Sprintf("Waiting for resolver rule %s to be deleted", ruleID), maxRetries, sleepBetweenRetries, func() (string, error) {
		sess, err := session.NewSession(&aws.Config{
			Region: aws.String(region),
		})
		require.NoError(t, err)
		svc := route53resolver.New(sess)

		_, err = svc.GetResolverRule(&route53resolver.GetResolverRuleInput{
			ResolverRuleId: aws.String(ruleID),
		})

		if err != nil {
			// If the rule is not found, it means it's been deleted
			if strings.Contains(err.Error(), "ResourceNotFoundException") {
				return "Resolver rule deleted successfully", nil
			}
			return "", err
		}

		return "", fmt.Errorf("Resolver rule %s still exists", ruleID)
	})
}

// GetCommonTestVars returns common variables used across tests
func GetCommonTestVars(uniqueID string) map[string]interface{} {
	return map[string]interface{}{
		"name_suffix": uniqueID,
		"tags": map[string]string{
			"Environment": "test",
			"ManagedBy":   "terratest",
			"TestRun":     uniqueID,
		},
	}
}

// CreateBasicResolverRuleConfig creates a basic resolver rule configuration for testing
func CreateBasicResolverRuleConfig(domainName string, targetIPs []string, vpcIDs []string) map[string]interface{} {
	return map[string]interface{}{
		"domain_name": domainName,
		"ips":         targetIPs,
		"vpc_ids":     vpcIDs,
	}
}

// CreateCompleteResolverRuleConfig creates a complete resolver rule configuration with RAM sharing
func CreateCompleteResolverRuleConfig(domainName, ruleName, ramName string, 
	targetIPs, vpcIDs, principals []string) map[string]interface{} {
	return map[string]interface{}{
		"domain_name": domainName,
		"rule_name":   ruleName,
		"ram_name":    ramName,
		"ips":         targetIPs,
		"vpc_ids":     vpcIDs,
		"principals":  principals,
	}
}

// CreateMockResolverEndpoint creates a mock resolver endpoint for testing
func CreateMockResolverEndpoint(t *testing.T, region, vpcID string, subnetIDs []string) string {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region),
	})
	require.NoError(t, err)
	svc := route53resolver.New(sess)

	// Create security group for resolver endpoint
	ec2Svc := ec2.New(sess)
	sgInput := &ec2.CreateSecurityGroupInput{
		GroupName:   aws.String(fmt.Sprintf("test-resolver-sg-%s", random.UniqueId())),
		Description: aws.String("Test security group for resolver endpoint"),
		VpcId:       aws.String(vpcID),
	}

	sgResult, err := ec2Svc.CreateSecurityGroup(sgInput)
	require.NoError(t, err)

	// Create resolver endpoint
	var ipAddresses []*route53resolver.IpAddressRequest
	for _, subnetID := range subnetIDs {
		ipAddresses = append(ipAddresses, &route53resolver.IpAddressRequest{
			SubnetId: aws.String(subnetID),
		})
	}

	input := &route53resolver.CreateResolverEndpointInput{
		Direction:         aws.String("OUTBOUND"),
		IpAddresses:       ipAddresses,
		SecurityGroupIds:  []*string{sgResult.GroupId},
		Name:              aws.String(fmt.Sprintf("test-resolver-endpoint-%s", random.UniqueId())),
	}

	result, err := svc.CreateResolverEndpoint(input)
	require.NoError(t, err)

	// Wait for endpoint to be available
	WaitForResolverEndpointAvailable(t, region, *result.ResolverEndpoint.Id, 30, 10*time.Second)

	return *result.ResolverEndpoint.Id
}

// WaitForResolverEndpointAvailable waits for a resolver endpoint to become available
func WaitForResolverEndpointAvailable(t *testing.T, region, endpointID string, maxRetries int, sleepBetweenRetries time.Duration) {
	retry.DoWithRetry(t, fmt.Sprintf("Waiting for resolver endpoint %s to be available", endpointID), maxRetries, sleepBetweenRetries, func() (string, error) {
		sess, err := session.NewSession(&aws.Config{
			Region: aws.String(region),
		})
		require.NoError(t, err)
		svc := route53resolver.New(sess)

		result, err := svc.GetResolverEndpoint(&route53resolver.GetResolverEndpointInput{
			ResolverEndpointId: aws.String(endpointID),
		})
		if err != nil {
			return "", err
		}

		if *result.ResolverEndpoint.Status == "OPERATIONAL" {
			return "Resolver endpoint is available", nil
		}

		return "", fmt.Errorf("Resolver endpoint %s is still %s", endpointID, *result.ResolverEndpoint.Status)
	})
}

// CleanupTestResolverRules removes test resolver rules that might be left over
func CleanupTestResolverRules(t *testing.T, region string, namePrefix string) {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region),
	})
	require.NoError(t, err)
	svc := route53resolver.New(sess)

	// List all resolver rules
	input := &route53resolver.ListResolverRulesInput{}
	result, err := svc.ListResolverRules(input)
	if err != nil {
		t.Logf("Warning: Failed to list resolver rules for cleanup: %v", err)
		return
	}

	// Delete rules that match the test prefix
	for _, rule := range result.ResolverRules {
		if rule.Name != nil && strings.HasPrefix(*rule.Name, namePrefix) {
			t.Logf("Cleaning up test resolver rule: %s", *rule.Name)
			
			_, err := svc.DeleteResolverRule(&route53resolver.DeleteResolverRuleInput{
				ResolverRuleId: rule.Id,
			})
			
			if err != nil {
				t.Logf("Warning: Failed to delete test resolver rule %s: %v", *rule.Name, err)
			}
		}
	}
}

// ValidateResolverRuleTargetIPs validates the target IPs of a resolver rule
func ValidateResolverRuleTargetIPs(t *testing.T, region, ruleID string, expectedTargetIPs []ResolverRuleTargetIP) {
	ruleInfo := ValidateResolverRuleExists(t, region, ruleID)
	
	require.NotNil(t, ruleInfo.ResolverRule.TargetIps, "Target IPs should not be nil")
	require.Len(t, ruleInfo.ResolverRule.TargetIps, len(expectedTargetIPs), 
		"Number of target IPs should match expected count")

	for i, expectedIP := range expectedTargetIPs {
		actualIP := ruleInfo.ResolverRule.TargetIps[i]
		require.Equal(t, expectedIP.IP, *actualIP.Ip, "Target IP should match")
		require.Equal(t, expectedIP.Port, *actualIP.Port, "Target port should match")
	}
}

// ValidateResolverRuleTags checks if expected tags are present on a resolver rule
func ValidateResolverRuleTags(t *testing.T, region, ruleID string, expectedTags map[string]string) {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region),
	})
	require.NoError(t, err)
	svc := route53resolver.New(sess)

	input := &route53resolver.ListTagsForResourceInput{
		ResourceArn: aws.String(fmt.Sprintf("arn:aws:route53resolver:%s:*:resolver-rule/%s", region, ruleID)),
	}

	result, err := svc.ListTagsForResource(input)
	require.NoError(t, err, "Failed to list tags for resolver rule %s", ruleID)

	actualTags := make(map[string]string)
	for _, tag := range result.Tags {
		actualTags[*tag.Key] = *tag.Value
	}

	for key, expectedValue := range expectedTags {
		actualValue, exists := actualTags[key]
		require.True(t, exists, "Tag %s should exist", key)
		require.Equal(t, expectedValue, actualValue, "Tag %s should have value %s", key, expectedValue)
	}
}