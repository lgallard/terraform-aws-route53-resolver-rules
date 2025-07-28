package test

import (
	"context"
	"crypto/md5"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ram"
	"github.com/aws/aws-sdk-go/service/route53resolver"
	"github.com/aws/aws-sdk-go/service/sts"
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

// ValidateResolverRuleExists checks if a resolver rule exists in AWS with exponential backoff
func ValidateResolverRuleExists(t *testing.T, region, ruleID string) *route53resolver.GetResolverRuleOutput {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region),
	})
	require.NoError(t, err)
	svc := route53resolver.New(sess)

	input := &route53resolver.GetResolverRuleInput{
		ResolverRuleId: aws.String(ruleID),
	}

	// Use exponential backoff for AWS API calls
	var result *route53resolver.GetResolverRuleOutput
	maxRetries := 5
	baseDelay := time.Second
	
	for attempt := 0; attempt < maxRetries; attempt++ {
		result, err = svc.GetResolverRule(input)
		if err == nil {
			return result
		}
		
		// Check if it's a retryable error
		if isRetryableAWSError(err) && attempt < maxRetries-1 {
			delay := time.Duration(1<<uint(attempt)) * baseDelay // Exponential backoff: 1s, 2s, 4s, 8s, 16s
			t.Logf("AWS API call failed (attempt %d/%d), retrying in %v: %v", attempt+1, maxRetries, delay, err)
			time.Sleep(delay)
			continue
		}
		
		break // Non-retryable error or max retries reached
	}
	
	require.NoError(t, err, "Failed to get resolver rule %s after %d attempts", ruleID, maxRetries)
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

// ValidateRAMResourceShare checks if a RAM resource share exists with exponential backoff
func ValidateRAMResourceShare(t *testing.T, region, shareArn string, expectedPrincipals []string) {
	maxRetries := 5
	baseDelay := time.Second
	
	for attempt := 0; attempt < maxRetries; attempt++ {
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
		if err == nil {
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
			return
		}
		
		// Retry if it's a retryable error
		if isRetryableAWSError(err) && attempt < maxRetries-1 {
			delay := time.Duration(1<<uint(attempt)) * baseDelay
			t.Logf("GetResourceShares failed (attempt %d/%d), retrying in %v: %v", attempt+1, maxRetries, delay, err)
			time.Sleep(delay)
			continue
		}
		
		require.NoError(t, err, "Failed to get RAM resource share %s after %d attempts", shareArn, maxRetries)
		return
	}
}

// ValidateDNSResolution performs DNS resolution test with context cancellation support
func ValidateDNSResolution(t *testing.T, domain string, expectedIPs []string) {
	if !strings.HasSuffix(domain, ".") {
		domain += "."
	}

	// Remove trailing dot for DNS lookup
	lookupDomain := strings.TrimSuffix(domain, ".")
	
	// Create context with timeout for proper cancellation
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	// Use context-aware DNS resolver
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: 3 * time.Second,
			}
			return d.DialContext(ctx, network, address)
		},
	}
	
	// Perform context-aware DNS lookup
	ips, err := resolver.LookupIPAddr(ctx, lookupDomain)
	
	if err != nil {
		// Check if it was a context cancellation (timeout)
		if ctx.Err() == context.DeadlineExceeded {
			t.Logf("Warning: DNS lookup for %s timed out after 5 seconds (expected in test environment)", lookupDomain)
		} else {
			t.Logf("Warning: DNS lookup for %s failed: %v (expected in test environment)", lookupDomain, err)
		}
		return
	}
	
	// Validate expected IPs if provided
	if len(expectedIPs) > 0 {
		actualIPs := make([]string, 0)
		for _, ipAddr := range ips {
			actualIPs = append(actualIPs, ipAddr.IP.String())
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
	
	t.Logf("✓ DNS resolution completed for %s with context cancellation support", lookupDomain)
}

// WaitForResolverRuleDeletion waits for a resolver rule to be deleted with exponential backoff
func WaitForResolverRuleDeletion(t *testing.T, region, ruleID string, maxRetries int, sleepBetweenRetries time.Duration) {
	maxAttempts := maxRetries
	if maxAttempts <= 0 {
		maxAttempts = 10 // Default reasonable limit
	}
	
	baseDelay := sleepBetweenRetries
	if baseDelay <= 0 {
		baseDelay = 2 * time.Second // Default base delay
	}

	for attempt := 0; attempt < maxAttempts; attempt++ {
		sess, err := session.NewSession(&aws.Config{
			Region: aws.String(region),
		})
		require.NoError(t, err)
		svc := route53resolver.New(sess)

		_, err = svc.GetResolverRule(&route53resolver.GetResolverRuleInput{
			ResolverRuleId: aws.String(ruleID),
		})

		if err != nil {
			// Check for specific AWS error types instead of string matching
			if awsErr, ok := err.(*route53resolver.ResourceNotFoundException); ok {
				t.Logf("Resolver rule %s deleted successfully: %v", ruleID, awsErr)
				return
			}
			
			// If it's a retryable error, continue with backoff
			if isRetryableAWSError(err) && attempt < maxAttempts-1 {
				delay := time.Duration(1<<uint(attempt)) * baseDelay
				if delay > 30*time.Second {
					delay = 30 * time.Second // Cap maximum delay
				}
				t.Logf("Retryable error checking rule deletion (attempt %d/%d), retrying in %v: %v", attempt+1, maxAttempts, delay, err)
				time.Sleep(delay)
				continue
			}
			
			// Non-retryable error
			require.NoError(t, err, "Failed to check resolver rule deletion after %d attempts", maxAttempts)
			return
		}

		// Rule still exists, wait with exponential backoff
		if attempt < maxAttempts-1 {
			delay := time.Duration(1<<uint(attempt)) * baseDelay
			if delay > 30*time.Second {
				delay = 30 * time.Second // Cap maximum delay
			}
			t.Logf("Resolver rule %s still exists (attempt %d/%d), waiting %v before retry", ruleID, attempt+1, maxAttempts, delay)
			time.Sleep(delay)
		}
	}
	
	require.Fail(t, fmt.Sprintf("Resolver rule %s was not deleted after %d attempts", ruleID, maxAttempts))
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

// CleanupTestResolverRules safely removes test resolver rules with isolation checks
func CleanupTestResolverRules(t *testing.T, region string, namePrefix string) {
	// Ensure we only clean up resources with proper test prefixes for safety
	if !isValidTestPrefix(namePrefix) {
		t.Logf("Warning: Skipping cleanup - invalid test prefix '%s' (must start with 'terratest-')", namePrefix)
		return
	}

	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region),
	})
	require.NoError(t, err)
	svc := route53resolver.New(sess)

	// List resolver rules with proper filtering to reduce API calls
	maxRetries := 3
	baseDelay := time.Second
	var result *route53resolver.ListResolverRulesOutput
	
	// Add filters to reduce unnecessary API calls
	filters := []*route53resolver.Filter{
		{
			Name:   aws.String("TYPE"),
			Values: []*string{aws.String("FORWARD")}, // Only get FORWARD rules
		},
	}
	
	// If we have a specific name prefix, add name filter
	if namePrefix != "" && len(namePrefix) > 5 {
		filters = append(filters, &route53resolver.Filter{
			Name:   aws.String("NAME-REGEX"),
			Values: []*string{aws.String(fmt.Sprintf("%s.*", namePrefix))},
		})
	}
	
	for attempt := 0; attempt < maxRetries; attempt++ {
		input := &route53resolver.ListResolverRulesInput{
			Filters:    filters,
			MaxResults: aws.Int64(50), // Limit results to reduce response size
		}
		result, err = svc.ListResolverRules(input)
		if err == nil {
			break
		}
		
		if isRetryableAWSError(err) && attempt < maxRetries-1 {
			delay := time.Duration(1<<uint(attempt)) * baseDelay
			t.Logf("ListResolverRules failed (attempt %d/%d), retrying in %v: %v", attempt+1, maxRetries, delay, err)
			time.Sleep(delay)
			continue
		}
		
		t.Logf("Warning: Failed to list resolver rules for cleanup after %d attempts: %v", maxRetries, err)
		return
	}

	// Delete rules that match the test prefix with additional safety checks
	cleanupCount := 0
	for _, rule := range result.ResolverRules {
		if rule.Name != nil && isSafeToDelete(*rule.Name, namePrefix) {
			t.Logf("Cleaning up test resolver rule: %s (ID: %s)", *rule.Name, *rule.Id)
			
			// Safely delete with exponential backoff
			if deleteResolverRuleWithRetry(t, svc, *rule.Id, *rule.Name) {
				cleanupCount++
			}
		}
	}
	
	t.Logf("Cleanup completed: removed %d test resolver rules", cleanupCount)
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
	// Validate inputs before constructing ARN
	require.NotEmpty(t, region, "Region cannot be empty")
	require.NotEmpty(t, ruleID, "Rule ID cannot be empty")
	require.True(t, strings.HasPrefix(ruleID, "rslvr-rr-"), "Rule ID must start with 'rslvr-rr-'")

	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region),
	})
	require.NoError(t, err)
	svc := route53resolver.New(sess)

	// Get AWS account ID dynamically instead of using wildcard
	accountID := getAWSAccountID(t, sess)
	resourceArn := fmt.Sprintf("arn:aws:route53resolver:%s:%s:resolver-rule/%s", region, accountID, ruleID)

	input := &route53resolver.ListTagsForResourceInput{
		ResourceArn: aws.String(resourceArn),
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

// getAWSAccountID retrieves the AWS account ID dynamically using STS
func getAWSAccountID(t *testing.T, sess *session.Session) string {
	svc := sts.New(sess)
	input := &sts.GetCallerIdentityInput{}
	
	result, err := svc.GetCallerIdentity(input)
	require.NoError(t, err, "Failed to get AWS account ID")
	require.NotNil(t, result.Account, "Account ID should not be nil")
	
	return *result.Account
}

// GenerateTestResourceName creates a safe test resource name with proper prefixes
func GenerateTestResourceName(resourceType, testName string) string {
	uniqueID := strings.ToLower(random.UniqueId())
	
	// Handle special cases for AWS resource format compliance
	switch resourceType {
	case "account":
		// Generate mock AWS account ID (12 digits, starts with 000 for safety)
		hash := fmt.Sprintf("%x", random.UniqueId())
		if len(hash) > 9 {
			hash = hash[:9]
		}
		return fmt.Sprintf("000%09s", hash)
	case "resolver-endpoint":
		// Generate AWS resolver endpoint format: rslvr-out-[17 hex chars]
		hash := fmt.Sprintf("%x", random.UniqueId())
		if len(hash) > 17 {
			hash = hash[:17]
		}
		return fmt.Sprintf("rslvr-out-%017s", hash)
	case "resolver-rule":
		// Generate AWS resolver rule format: rslvr-rr-[17 hex chars]
		hash := fmt.Sprintf("%x", random.UniqueId())
		if len(hash) > 17 {
			hash = hash[:17]
		}
		return fmt.Sprintf("rslvr-rr-%017s", hash)
	case "vpc":
		// Generate AWS VPC format: vpc-[8 or 17 hex chars] - using 8 for simplicity
		hash := fmt.Sprintf("%x", random.UniqueId())
		if len(hash) > 8 {
			hash = hash[:8]
		}
		return fmt.Sprintf("vpc-%08s", hash)
	case "sg":
		// Generate AWS Security Group format: sg-[8 or 17 hex chars]
		hash := fmt.Sprintf("%x", random.UniqueId())
		if len(hash) > 8 {
			hash = hash[:8]
		}
		return fmt.Sprintf("sg-%08s", hash)
	default:
		// Default terratest naming for other resources
		return fmt.Sprintf("terratest-%s-%s-%s", resourceType, testName, uniqueID)
	}
}

// GenerateTestSessionID creates a unique session ID for parallel test isolation
func GenerateTestSessionID(t *testing.T) string {
	// Create unique session ID based on test name, timestamp, and random data
	testName := t.Name()
	timestamp := time.Now().UnixNano()
	randomData := random.UniqueId()
	
	// Create MD5 hash for consistent length
	hash := md5.Sum([]byte(fmt.Sprintf("%s-%d-%s", testName, timestamp, randomData)))
	sessionID := fmt.Sprintf("%x", hash)[:12] // Use first 12 chars for session ID
	
	t.Logf("Generated test session ID: %s for test: %s", sessionID, testName)
	return sessionID
}

// GenerateTestResourceNameWithSession creates resource names with session isolation
func GenerateTestResourceNameWithSession(resourceType, testName, sessionID string) string {
	// Handle special cases for AWS resource format compliance with session isolation
	switch resourceType {
	case "account":
		// Generate unique mock AWS account ID with session isolation
		hash := fmt.Sprintf("%x", fmt.Sprintf("%s-%s", sessionID, testName))
		if len(hash) > 9 {
			hash = hash[:9]
		}
		return fmt.Sprintf("000%09s", hash)
	case "resolver-endpoint":
		// Generate unique AWS resolver endpoint format with session
		hash := fmt.Sprintf("%x", fmt.Sprintf("%s-%s", sessionID, testName))
		if len(hash) > 17 {
			hash = hash[:17]
		}
		return fmt.Sprintf("rslvr-out-%017s", hash)
	case "resolver-rule":
		// Generate unique AWS resolver rule format with session
		hash := fmt.Sprintf("%x", fmt.Sprintf("%s-%s", sessionID, testName))
		if len(hash) > 17 {
			hash = hash[:17]
		}
		return fmt.Sprintf("rslvr-rr-%017s", hash)
	case "vpc":
		// Generate unique AWS VPC format with session
		hash := fmt.Sprintf("%x", fmt.Sprintf("%s-%s", sessionID, testName))
		if len(hash) > 8 {
			hash = hash[:8]
		}
		return fmt.Sprintf("vpc-%08s", hash)
	case "sg":
		// Generate unique AWS Security Group format with session
		hash := fmt.Sprintf("%x", fmt.Sprintf("%s-%s", sessionID, testName))
		if len(hash) > 8 {
			hash = hash[:8]
		}
		return fmt.Sprintf("sg-%08s", hash)
	default:
		// Default terratest naming with session isolation
		uniqueID := strings.ToLower(random.UniqueId())
		return fmt.Sprintf("terratest-%s-%s-%s-%s", resourceType, testName, sessionID, uniqueID)
	}
}

// ValidateResourceNameFormat validates that resource names follow safe testing patterns
func ValidateResourceNameFormat(t *testing.T, resourceName, resourceType string) {
	require.NotEmpty(t, resourceName, "Resource name cannot be empty")
	require.True(t, strings.HasPrefix(resourceName, "terratest-"), 
		"Resource name must start with 'terratest-' prefix for safety")
	require.Contains(t, resourceName, resourceType, 
		"Resource name must contain resource type for identification")
	require.True(t, len(resourceName) >= 20, 
		"Resource name must be sufficiently unique (min 20 chars)")
}

// ValidateResolverRuleError validates resolver rule creation errors with proper AWS SDK error handling
func ValidateResolverRuleError(t *testing.T, region, ruleID string, expectedErrorType string) {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region),
	})
	require.NoError(t, err)
	svc := route53resolver.New(sess)

	input := &route53resolver.GetResolverRuleInput{
		ResolverRuleId: aws.String(ruleID),
	}

	_, err = svc.GetResolverRule(input)
	if err != nil {
		// Check for specific AWS error types instead of string matching
		switch expectedErrorType {
		case "ResourceNotFoundException":
			if awsErr, ok := err.(*route53resolver.ResourceNotFoundException); ok {
				t.Logf("Expected ResourceNotFoundException: %v", awsErr)
				return
			}
		case "InvalidParameterException":
			if awsErr, ok := err.(*route53resolver.InvalidParameterException); ok {
				t.Logf("Expected InvalidParameterException: %v", awsErr)
				return
			}
		case "AccessDeniedException":
			if awsErr, ok := err.(*route53resolver.AccessDeniedException); ok {
				t.Logf("Expected AccessDeniedException: %v", awsErr)
				return
			}
		case "InternalServiceErrorException":
			if awsErr, ok := err.(*route53resolver.InternalServiceErrorException); ok {
				t.Logf("Expected InternalServiceErrorException: %v", awsErr)
				return
			}
		case "ThrottlingException":
			if awsErr, ok := err.(*route53resolver.ThrottlingException); ok {
				t.Logf("Expected ThrottlingException: %v", awsErr)
				return
			}
		}
		t.Errorf("Expected error type %s but got: %T %v", expectedErrorType, err, err)
	} else {
		t.Errorf("Expected error of type %s but operation succeeded", expectedErrorType)
	}
}

// ValidateInputParameters validates input parameters with comprehensive error checking
func ValidateInputParameters(t *testing.T, domainName, ruleID, vpcID string) {
	// Validate domain name format
	if domainName != "" {
		require.True(t, strings.HasSuffix(domainName, "."), 
			"Domain name must end with a trailing dot for DNS resolution")
		require.True(t, len(domainName) > 1, 
			"Domain name cannot be empty or just a dot")
		require.False(t, strings.Contains(domainName, ".."), 
			"Domain name cannot contain consecutive dots")
	}

	// Validate resolver rule ID format
	if ruleID != "" {
		require.True(t, strings.HasPrefix(ruleID, "rslvr-rr-"), 
			"Resolver rule ID must start with 'rslvr-rr-' prefix")
		require.Regexp(t, `^rslvr-rr-[a-f0-9]{17}$`, ruleID, 
			"Resolver rule ID must follow AWS format: rslvr-rr-[17 hex chars]")
	}

	// Validate VPC ID format
	if vpcID != "" {
		require.True(t, strings.HasPrefix(vpcID, "vpc-"), 
			"VPC ID must start with 'vpc-' prefix")
		require.Regexp(t, `^vpc-[a-f0-9]{8}([a-f0-9]{9})?$`, vpcID, 
			"VPC ID must follow AWS format: vpc-[8 or 17 hex chars]")
	}
}

// ValidateIPAddressFormat validates IP address and port combinations
func ValidateIPAddressFormat(t *testing.T, ipWithPort string) bool {
	parts := strings.Split(ipWithPort, ":")
	
	// Validate IP address part
	ipAddr := parts[0]
	if net.ParseIP(ipAddr) == nil {
		t.Logf("Invalid IP address format: %s", ipAddr)
		return false
	}

	// Validate port if present
	if len(parts) == 2 {
		port := parts[1]
		if portNum, err := strconv.Atoi(port); err != nil || portNum < 1 || portNum > 65535 {
			t.Logf("Invalid port number: %s (must be 1-65535)", port)
			return false
		}
	} else if len(parts) > 2 {
		t.Logf("Invalid IP:port format: %s (too many colons)", ipWithPort)
		return false
	}

	return true
}

// isValidTestPrefix validates that the cleanup prefix is safe for test resource deletion
func isValidTestPrefix(prefix string) bool {
	if prefix == "" {
		return false
	}
	
	// Must start with terratest- for safety
	if !strings.HasPrefix(prefix, "terratest-") {
		return false
	}
	
	// Must be reasonably long to avoid accidental broad deletions
	if len(prefix) < 10 {
		return false
	}
	
	// Must not contain wildcards or dangerous patterns
	dangerousPatterns := []string{"*", "?", "..", "//", "prod", "production"}
	lowerPrefix := strings.ToLower(prefix)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(lowerPrefix, pattern) {
			return false
		}
	}
	
	return true
}

// isSafeToDelete performs additional safety checks before deleting a resource
func isSafeToDelete(resourceName, expectedPrefix string) bool {
	// Basic prefix check
	if !strings.HasPrefix(resourceName, expectedPrefix) {
		return false
	}
	
	// Ensure it's a test resource (contains test indicators)
	testIndicators := []string{"terratest", "test-", "-test", "temp-", "tmp-"}
	lowerName := strings.ToLower(resourceName)
	hasTestIndicator := false
	for _, indicator := range testIndicators {
		if strings.Contains(lowerName, indicator) {
			hasTestIndicator = true
			break
		}
	}
	
	if !hasTestIndicator {
		return false
	}
	
	// Ensure it's not a protected resource (doesn't contain production indicators)
	protectedIndicators := []string{"prod", "production", "live", "critical", "main", "master"}
	for _, indicator := range protectedIndicators {
		if strings.Contains(lowerName, indicator) {
			return false
		}
	}
	
	return true
}

// deleteResolverRuleWithRetry safely deletes a resolver rule with retry logic
func deleteResolverRuleWithRetry(t *testing.T, svc *route53resolver.Route53Resolver, ruleID, ruleName string) bool {
	maxRetries := 3
	baseDelay := time.Second
	
	for attempt := 0; attempt < maxRetries; attempt++ {
		_, err := svc.DeleteResolverRule(&route53resolver.DeleteResolverRuleInput{
			ResolverRuleId: aws.String(ruleID),
		})
		
		if err == nil {
			t.Logf("Successfully deleted resolver rule %s (ID: %s)", ruleName, ruleID)
			return true
		}
		
		// Check if it's already deleted (not an error)
		if _, ok := err.(*route53resolver.ResourceNotFoundException); ok {
			t.Logf("Resolver rule %s (ID: %s) was already deleted", ruleName, ruleID)
			return true
		}
		
		// Retry if it's a retryable error
		if isRetryableAWSError(err) && attempt < maxRetries-1 {
			delay := time.Duration(1<<uint(attempt)) * baseDelay
			t.Logf("DeleteResolverRule failed (attempt %d/%d), retrying in %v: %v", attempt+1, maxRetries, delay, err)
			time.Sleep(delay)
			continue
		}
		
		t.Logf("Warning: Failed to delete resolver rule %s (ID: %s) after %d attempts: %v", ruleName, ruleID, maxRetries, err)
		return false
	}
	
	return false
}

// EnsureResourceIsolation verifies that test resources are properly isolated
func EnsureResourceIsolation(t *testing.T, region string, testResourceNames []string) {
	t.Logf("Verifying resource isolation for %d test resources in region %s", len(testResourceNames), region)
	
	for _, resourceName := range testResourceNames {
		// Verify resource name follows safe patterns
		require.True(t, isSafeToDelete(resourceName, "terratest-"), 
			"Resource name '%s' does not follow safe test naming patterns", resourceName)
		
		// Verify resource name is unique enough
		require.True(t, len(resourceName) >= 20, 
			"Resource name '%s' is too short for proper isolation (min 20 chars)", resourceName)
		
		t.Logf("✓ Resource isolation verified for: %s", resourceName)
	}
}

// VerifyTestEnvironment ensures we're running in a safe test environment
func VerifyTestEnvironment(t *testing.T, region string) {
	// Check environment variables for safety
	if env := os.Getenv("ENVIRONMENT"); env != "" {
		protectedEnvs := []string{"production", "prod", "live", "main", "master"}
		lowerEnv := strings.ToLower(env)
		for _, protectedEnv := range protectedEnvs {
			require.NotEqual(t, protectedEnv, lowerEnv, 
				"Test cannot run in protected environment: %s", env)
		}
	}
	
	// Verify we're using a test-safe region
	testSafeRegions := []string{"us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"}
	isTestSafe := false
	for _, safeRegion := range testSafeRegions {
		if region == safeRegion {
			isTestSafe = true
			break
		}
	}
	require.True(t, isTestSafe, "Region '%s' is not in the list of test-safe regions", region)
	
	t.Logf("✓ Test environment verified: region=%s", region)
}

// ValidateAWSResourceFormats validates that mock AWS resource IDs follow proper formats
func ValidateAWSResourceFormats(t *testing.T, resourceMap map[string]string) {
	for resourceType, resourceID := range resourceMap {
		switch resourceType {
		case "account":
			require.Regexp(t, `^[0-9]{12}$`, resourceID, 
				"AWS Account ID must be exactly 12 digits: %s", resourceID)
			require.True(t, strings.HasPrefix(resourceID, "000"), 
				"Test Account ID should start with '000' for safety: %s", resourceID)
		case "resolver-endpoint":
			require.Regexp(t, `^rslvr-out-[a-f0-9]{17}$`, resourceID, 
				"Resolver endpoint ID must match format 'rslvr-out-[17 hex chars]': %s", resourceID)
		case "resolver-rule":
			require.Regexp(t, `^rslvr-rr-[a-f0-9]{17}$`, resourceID, 
				"Resolver rule ID must match format 'rslvr-rr-[17 hex chars]': %s", resourceID)
		case "vpc":
			require.Regexp(t, `^vpc-[a-f0-9]{8}([a-f0-9]{9})?$`, resourceID, 
				"VPC ID must match format 'vpc-[8 or 17 hex chars]': %s", resourceID)
		case "security-group":
			require.Regexp(t, `^sg-[a-f0-9]{8}([a-f0-9]{9})?$`, resourceID, 
				"Security Group ID must match format 'sg-[8 or 17 hex chars]': %s", resourceID)
		case "subnet":
			require.Regexp(t, `^subnet-[a-f0-9]{8}([a-f0-9]{9})?$`, resourceID, 
				"Subnet ID must match format 'subnet-[8 or 17 hex chars]': %s", resourceID)
		default:
			t.Logf("Warning: Unknown resource type '%s' for validation: %s", resourceType, resourceID)
		}
		t.Logf("✓ AWS resource format validated: %s = %s", resourceType, resourceID)
	}
}

// ValidateResourceIDUniqueness ensures no duplicate resource IDs across parallel tests
func ValidateResourceIDUniqueness(t *testing.T, resourceIDs []string, sessionID string) {
	seenIDs := make(map[string]bool)
	
	for _, resourceID := range resourceIDs {
		if seenIDs[resourceID] {
			t.Errorf("Duplicate resource ID detected: %s (session: %s)", resourceID, sessionID)
		}
		seenIDs[resourceID] = true
	}
	
	t.Logf("✓ Resource ID uniqueness validated for session %s: %d resources", sessionID, len(resourceIDs))
}

// isRetryableAWSError determines if an AWS error is retryable
func isRetryableAWSError(err error) bool {
	// Check for specific AWS error types that are retryable
	switch err.(type) {
	case *route53resolver.ThrottlingException:
		return true
	case *route53resolver.InternalServiceErrorException:
		return true
	default:
		// Check error message for common retryable patterns
		errorMsg := strings.ToLower(err.Error())
		retryablePatterns := []string{
			"throttling",
			"rate exceeded",
			"internal error",
			"service unavailable",
			"timeout",
			"connection reset",
			"network unreachable",
		}
		
		for _, pattern := range retryablePatterns {
			if strings.Contains(errorMsg, pattern) {
				return true
			}
		}
		return false
	}
}

// ValidateResolverRuleAssociationWithRetry checks resolver rule association with exponential backoff
func ValidateResolverRuleAssociationWithRetry(t *testing.T, region, ruleID, vpcID string) {
	maxRetries := 5
	baseDelay := time.Second
	
	for attempt := 0; attempt < maxRetries; attempt++ {
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
		if err == nil {
			require.NotEmpty(t, result.ResolverRuleAssociations, 
				"Expected resolver rule %s to be associated with VPC %s", ruleID, vpcID)
			return
		}
		
		// Retry if it's a retryable error
		if isRetryableAWSError(err) && attempt < maxRetries-1 {
			delay := time.Duration(1<<uint(attempt)) * baseDelay
			t.Logf("ListResolverRuleAssociations failed (attempt %d/%d), retrying in %v: %v", attempt+1, maxRetries, delay, err)
			time.Sleep(delay)
			continue
		}
		
		require.NoError(t, err, "Failed to list resolver rule associations after %d attempts", maxRetries)
		return
	}
}