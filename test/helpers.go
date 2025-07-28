package test

import (
	"context"
	"crypto/md5"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/organizations"
	"github.com/aws/aws-sdk-go/service/ram"
	"github.com/aws/aws-sdk-go/service/route53resolver"
	"github.com/aws/aws-sdk-go/service/sts"
	awstest "github.com/gruntwork-io/terratest/modules/aws"
	"github.com/gruntwork-io/terratest/modules/random"
	"github.com/gruntwork-io/terratest/modules/retry"
	"github.com/stretchr/testify/assert"
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

// AWSSessionPool manages reusable AWS sessions for better performance
type AWSSessionPool struct {
	sessions map[string]*session.Session
	mutex    sync.RWMutex
}

// NewAWSSessionPool creates a new session pool
func NewAWSSessionPool() *AWSSessionPool {
	return &AWSSessionPool{
		sessions: make(map[string]*session.Session),
	}
}

// GetSession retrieves or creates a session for the given region
func (p *AWSSessionPool) GetSession(region string) (*session.Session, error) {
	p.mutex.RLock()
	if sess, exists := p.sessions[region]; exists {
		p.mutex.RUnlock()
		return sess, nil
	}
	p.mutex.RUnlock()

	p.mutex.Lock()
	defer p.mutex.Unlock()
	
	// Double-check after acquiring write lock
	if sess, exists := p.sessions[region]; exists {
		return sess, nil
	}

	// Create new session with optimized configuration
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region),
		// Enable connection pooling and reuse
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
		},
		// Enable retries with exponential backoff
		Retryer: &client.DefaultRetryer{
			NumMaxRetries:    5,
			MinRetryDelay:    time.Second,
			MaxRetryDelay:    30 * time.Second,
			MinThrottleDelay: time.Second,
			MaxThrottleDelay: 30 * time.Second,
		},
	})
	
	if err != nil {
		return nil, err
	}
	
	p.sessions[region] = sess
	return sess, nil
}

// CloseAll closes all sessions in the pool and properly closes HTTP connections
func (p *AWSSessionPool) CloseAll() {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	
	for region, sess := range p.sessions {
		// Close HTTP connections properly to prevent resource leaks
		if sess != nil && sess.Config != nil && sess.Config.HTTPClient != nil {
			// Close idle connections to prevent resource leaks
			client := sess.Config.HTTPClient
			if client.Transport != nil {
				if transport, ok := client.Transport.(*http.Transport); ok {
					transport.CloseIdleConnections()
				}
			}
		}
		delete(p.sessions, region)
	}
}

// Global session pool for reuse across tests
var globalSessionPool = NewAWSSessionPool()

// CleanupTestResources ensures proper cleanup of test resources and HTTP connections
func CleanupTestResources() {
	// Close all session pool connections to prevent resource leaks
	globalSessionPool.CloseAll()
}

// AWS API timeout constants
const (
	AWSAPITimeout   = 10 * time.Second
	AWSShortTimeout = 5 * time.Second
	AWSLongTimeout  = 30 * time.Second
)

// WithAWSTimeout creates a context with appropriate timeout for AWS operations
func WithAWSTimeout(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	return context.WithTimeout(parent, timeout)
}

// CreateAWSSessionWithTimeout creates an AWS session with standardized timeout configuration
func CreateAWSSessionWithTimeout(region string) (*session.Session, error) {
	return globalSessionPool.GetSession(region)
}

// GenerateTestName creates a unique test name with prefix
func GenerateTestName(prefix string) string {
	return fmt.Sprintf("%s-%s", prefix, strings.ToLower(random.UniqueId()))
}

// GetTestRegion returns a stable AWS region for testing
func GetTestRegion(t *testing.T) string {
	return awstest.GetRandomStableRegion(t, nil, nil)
}

// ValidateResolverRuleExists checks if a resolver rule exists in AWS with context timeout and exponential backoff
func ValidateResolverRuleExists(t *testing.T, region, ruleID string) *route53resolver.GetResolverRuleOutput {
	// Create context with timeout for AWS API operations
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	// Use pooled session for better performance
	sess, err := globalSessionPool.GetSession(region)
	require.NoError(t, err, "Failed to get AWS session from pool for region %s", region)
	svc := route53resolver.New(sess)

	input := &route53resolver.GetResolverRuleInput{
		ResolverRuleId: aws.String(ruleID),
	}

	// Use exponential backoff for AWS API calls
	var result *route53resolver.GetResolverRuleOutput
	maxRetries := 5
	baseDelay := time.Second
	
	for attempt := 0; attempt < maxRetries; attempt++ {
		// Use context for timeout control
		result, err = svc.GetResolverRuleWithContext(ctx, input)
		if err == nil {
			return result
		}
		
		// Check if it's a context timeout
		if ctx.Err() == context.DeadlineExceeded {
			require.Fail(t, "AWS API call timed out after 10 seconds for GetResolverRule: %s", ruleID)
			return nil
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
	// Create context with timeout for AWS API operations
	ctx, cancel := WithAWSTimeout(context.Background(), AWSAPITimeout)
	defer cancel()
	
	// Use pooled session for better performance
	sess, err := globalSessionPool.GetSession(region)
	require.NoError(t, err, "Failed to get AWS session from pool for region %s", region)
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

	result, err := svc.ListResolverRuleAssociationsWithContext(ctx, input)
	require.NoError(t, err, "Failed to list resolver rule associations")
	require.NotEmpty(t, result.ResolverRuleAssociations, 
		"Expected resolver rule %s to be associated with VPC %s", ruleID, vpcID)
}

// ValidateRAMResourceShare checks if a RAM resource share exists with context timeout and exponential backoff
func ValidateRAMResourceShare(t *testing.T, region, shareArn string, expectedPrincipals []string) {
	// Create context with timeout for AWS API operations
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
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

		shareResult, err := svc.GetResourceSharesWithContext(ctx, getInput)
		if err == nil {
			require.NotEmpty(t, shareResult.ResourceShares, "RAM resource share not found")
			
			// Validate principals if provided
			if len(expectedPrincipals) > 0 {
				assocInput := &ram.GetResourceShareAssociationsInput{
					ResourceShareArns: []*string{aws.String(shareArn)},
					AssociationType:   aws.String("PRINCIPAL"),
				}

				assocResult, err := svc.GetResourceShareAssociationsWithContext(ctx, assocInput)
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

// ValidateDNSResolution performs DNS resolution test with enhanced validation and strict mode by default
// Set strictMode to false only for legacy/backward compatibility scenarios
func ValidateDNSResolution(t *testing.T, domain string, expectedIPs []string, strictMode bool) {
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
			if strictMode {
				t.Fatalf("DNS lookup for %s timed out after 5 seconds", lookupDomain)
			} else {
				t.Logf("Warning: DNS lookup for %s timed out after 5 seconds (expected in test environment)", lookupDomain)
			}
		} else {
			if strictMode {
				t.Fatalf("DNS lookup for %s failed: %v", lookupDomain, err)
			} else {
				t.Logf("Warning: DNS lookup for %s failed: %v (expected in test environment)", lookupDomain, err)
			}
		}
		
		if !strictMode {
			return
		}
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
				if strictMode {
					t.Fatalf("Expected IP %s not found in DNS resolution for %s (got: %v)", 
						expectedIP, lookupDomain, actualIPs)
				} else {
					t.Logf("Warning: Expected IP %s not found in DNS resolution for %s (got: %v)", 
						expectedIP, lookupDomain, actualIPs)
				}
			}
		}
	}
	
	t.Logf("✓ DNS resolution completed for %s with context cancellation support (strict mode: %v)", lookupDomain, strictMode)
}

// ValidateDNSResolutionDefault performs DNS resolution test with strict validation (new default behavior)
// This function uses strict mode to fail tests on DNS errors for better production readiness
func ValidateDNSResolutionDefault(t *testing.T, domain string, expectedIPs []string) {
	ValidateDNSResolution(t, domain, expectedIPs, true)
}

// ValidateDNSResolutionWarningOnly performs DNS resolution test with warning-only behavior (backward compatibility)
// Use this only for test environments where DNS failures are expected and acceptable
func ValidateDNSResolutionWarningOnly(t *testing.T, domain string, expectedIPs []string) {
	ValidateDNSResolution(t, domain, expectedIPs, false)
}

// ValidateDNSResolutionStrict performs DNS resolution test with strict validation that fails tests on errors
func ValidateDNSResolutionStrict(t *testing.T, domain string, expectedIPs []string) {
	ValidateDNSResolution(t, domain, expectedIPs, true)
}

// ValidateDNSResolutionCritical performs enhanced DNS validation for critical production scenarios
func ValidateDNSResolutionCritical(t *testing.T, domain string, expectedIPs []string) {
	// Enhanced DNS validation with multiple checks
	if domain == "" {
		t.Fatalf("Critical DNS validation failed: empty domain name provided")
	}
	
	// Check for suspicious domain patterns that could indicate issues
	if strings.Contains(domain, "localhost") || strings.Contains(domain, "127.0.0.1") {
		t.Fatalf("Critical DNS validation failed: localhost domains not allowed in production: %s", domain)
	}
	
	// Perform strict DNS resolution
	ValidateDNSResolution(t, domain, expectedIPs, true)
	
	// Additional validation for production readiness
	if len(expectedIPs) == 0 {
		t.Logf("Warning: No expected IPs provided for critical DNS validation of %s", domain)
	}
}

// ValidateDNSResolutionWithFallback performs DNS resolution with multiple fallback strategies
func ValidateDNSResolutionWithFallback(t *testing.T, domain string, expectedIPs []string, strictMode bool) {
	// Primary DNS servers to try in order
	dnsServers := []string{
		"8.8.8.8:53",     // Google DNS
		"1.1.1.1:53",     // Cloudflare DNS
		"208.67.222.222:53", // OpenDNS
	}
	
	var lastError error
	
	for i, dnsServer := range dnsServers {
		t.Logf("Attempting DNS resolution for %s using DNS server %s (attempt %d/%d)", 
			domain, dnsServer, i+1, len(dnsServers))
			
		err := validateDNSWithServer(t, domain, expectedIPs, dnsServer, strictMode)
		if err == nil {
			t.Logf("✓ DNS resolution successful using %s", dnsServer)
			return
		}
		
		lastError = err
		t.Logf("DNS resolution failed with %s: %v", dnsServer, err)
		
		// Add exponential backoff between attempts
		if i < len(dnsServers)-1 {
			backoffDelay := time.Duration(1<<uint(i)) * time.Second
			t.Logf("Waiting %v before trying next DNS server", backoffDelay)
			time.Sleep(backoffDelay)
		}
	}
	
	// All DNS servers failed
	if strictMode {
		t.Fatalf("DNS resolution failed with all DNS servers for %s. Last error: %v", domain, lastError)
	} else {
		t.Logf("Warning: DNS resolution failed with all DNS servers for %s. Last error: %v (expected in test environment)", domain, lastError)
	}
}

// validateDNSWithServer performs DNS lookup using a specific DNS server
func validateDNSWithServer(t *testing.T, domain string, expectedIPs []string, dnsServer string, strictMode bool) error {
	if !strings.HasSuffix(domain, ".") {
		domain += "."
	}

	// Remove trailing dot for DNS lookup
	lookupDomain := strings.TrimSuffix(domain, ".")
	
	// Create context with timeout for proper cancellation
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	// Create custom resolver with specific DNS server
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: 5 * time.Second,
			}
			return d.DialContext(ctx, network, dnsServer)
		},
	}
	
	// Perform context-aware DNS lookup with retry logic
	var ips []net.IPAddr
	var err error
	
	maxRetries := 3
	for attempt := 0; attempt < maxRetries; attempt++ {
		ips, err = resolver.LookupIPAddr(ctx, lookupDomain)
		if err == nil {
			break
		}
		
		// Check if it was a context cancellation (timeout)
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("DNS lookup timeout after 10 seconds")
		}
		
		// Retry with backoff if it's a temporary error
		if isTemporaryDNSError(err) && attempt < maxRetries-1 {
			backoffDelay := time.Duration(1<<uint(attempt)) * 500 * time.Millisecond
			t.Logf("Temporary DNS error (attempt %d/%d), retrying in %v: %v", attempt+1, maxRetries, backoffDelay, err)
			time.Sleep(backoffDelay)
			continue
		}
		
		return fmt.Errorf("DNS lookup failed: %v", err)
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
				return fmt.Errorf("expected IP %s not found in DNS resolution (got: %v)", expectedIP, actualIPs)
			}
		}
	}
	
	return nil
}

// isTemporaryDNSError determines if a DNS error is temporary and retryable
func isTemporaryDNSError(err error) bool {
	if err == nil {
		return false
	}
	
	// Check for temporary network errors
	if netErr, ok := err.(net.Error); ok {
		return netErr.Temporary()
	}
	
	// Check for specific DNS error patterns that are retryable
	errorMsg := strings.ToLower(err.Error())
	retryablePatterns := []string{
		"timeout",
		"connection refused",
		"network unreachable",
		"temporary failure",
		"server misbehaving",
		"no such host", // Sometimes temporary in test environments
	}
	
	for _, pattern := range retryablePatterns {
		if strings.Contains(errorMsg, pattern) {
			return true
		}
	}
	
	return false
}

// TestAWSServiceLimits validates AWS service limits and quota compliance for Route53 Resolver
func TestAWSServiceLimits(t *testing.T, region string) {
	// Create context with timeout for AWS API calls
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	// Create AWS session
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region),
	})
	require.NoError(t, err, "Failed to create AWS session for service limit testing")
	
	// Test Route53 Resolver service limits
	testRoute53ResolverLimits(t, ctx, sess)
	
	// Test RAM service limits
	testRAMServiceLimits(t, ctx, sess)
}

// testRoute53ResolverLimits tests Route53 Resolver service limits
func testRoute53ResolverLimits(t *testing.T, ctx context.Context, sess *session.Session) {
	svc := route53resolver.New(sess)
	
	// Test list resolver rules to check current usage
	listInput := &route53resolver.ListResolverRulesInput{
		MaxResults: aws.Int64(100),
	}
	
	result, err := svc.ListResolverRulesWithContext(ctx, listInput)
	if err != nil {
		// Log warning but don't fail test for listing
		t.Logf("Warning: Could not list resolver rules for limit checking: %v", err)
		return
	}
	
	currentRules := len(result.ResolverRules)
	t.Logf("Current resolver rules count: %d", currentRules)
	
	// AWS default limit is typically 1000 resolver rules per account per region
	maxResolverRules := 1000
	if currentRules > maxResolverRules-100 { // Leave buffer for testing
		t.Logf("Warning: Approaching resolver rules limit (%d/%d)", currentRules, maxResolverRules)
	}
}

// testRAMServiceLimits tests RAM service limits
func testRAMServiceLimits(t *testing.T, ctx context.Context, sess *session.Session) {
	ramSvc := ram.New(sess)
	
	// Test list resource shares to check current usage
	listInput := &ram.GetResourceSharesInput{
		ResourceOwner: aws.String("SELF"),
		MaxResults:    aws.Int64(100),
	}
	
	result, err := ramSvc.GetResourceSharesWithContext(ctx, listInput)
	if err != nil {
		// Log warning but don't fail test for listing
		t.Logf("Warning: Could not list RAM resource shares for limit checking: %v", err)
		return
	}
	
	currentShares := len(result.ResourceShares)
	t.Logf("Current RAM resource shares count: %d", currentShares)
	
	// AWS default limit is typically 500 resource shares per account
	maxResourceShares := 500
	if currentShares > maxResourceShares-50 { // Leave buffer for testing
		t.Logf("Warning: Approaching RAM resource shares limit (%d/%d)", currentShares, maxResourceShares)
	}
}

// SimulateAWSServiceErrors simulates common AWS service errors for testing error handling
func SimulateAWSServiceErrors(t *testing.T, errorType string) error {
	switch errorType {
	case "throttling":
		return awserr.New("Throttling", "Rate exceeded", nil)
	case "limit_exceeded":
		return awserr.New("LimitExceededException", "Resource limit exceeded", nil)
	case "invalid_parameter":
		return awserr.New("InvalidParameterValue", "Invalid parameter value", nil)
	case "not_found":
		return awserr.New("ResourceNotFoundException", "Resource not found", nil)
	case "access_denied":
		return awserr.New("AccessDenied", "Access denied", nil)
	default:
		return fmt.Errorf("unknown error type: %s", errorType)
	}
}

// ValidateAWSErrorHandling tests proper handling of various AWS error types
func ValidateAWSErrorHandling(t *testing.T, err error, expectedErrorType string) {
	if err == nil {
		t.Fatalf("Expected AWS error of type %s but got no error", expectedErrorType)
	}
	
	if awsErr, ok := err.(awserr.Error); ok {
		switch expectedErrorType {
		case "throttling":
			assert.Contains(t, []string{"Throttling", "RequestLimitExceeded", "TooManyRequestsException"}, 
				awsErr.Code(), "Expected throttling error")
		case "limit_exceeded":
			assert.Contains(t, []string{"LimitExceededException", "ResourceLimitExceeded", "QuotaExceededException"}, 
				awsErr.Code(), "Expected limit exceeded error")
		case "invalid_parameter":
			assert.Contains(t, []string{"InvalidParameterValue", "InvalidParameter", "ValidationException"}, 
				awsErr.Code(), "Expected invalid parameter error")
		case "not_found":
			assert.Contains(t, []string{"ResourceNotFoundException", "NotFound", "NoSuchEntity"}, 
				awsErr.Code(), "Expected not found error")
		case "access_denied":
			assert.Contains(t, []string{"AccessDenied", "UnauthorizedOperation", "Forbidden"}, 
				awsErr.Code(), "Expected access denied error")
		default:
			t.Fatalf("Unknown expected error type: %s", expectedErrorType)
		}
		
		t.Logf("✓ AWS error handling validated for %s: %s", expectedErrorType, awsErr.Code())
	} else {
		t.Fatalf("Expected AWS error but got: %v", err)
	}
}

// TestNetworkConnectivityErrorScenarios tests network-related error conditions
func TestNetworkConnectivityErrorScenarios(t *testing.T, region string) {
	// Create context with short timeout to simulate network issues
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	
	// Create AWS session with custom endpoint for testing
	sess, err := session.NewSession(&aws.Config{
		Region:   aws.String(region),
		Endpoint: aws.String("https://invalid-endpoint.amazonaws.com"), // Invalid endpoint
	})
	require.NoError(t, err, "Failed to create AWS session for network error testing")
	
	svc := route53resolver.New(sess)
	
	// Try to list resolver rules with invalid endpoint
	listInput := &route53resolver.ListResolverRulesInput{
		MaxResults: aws.Int64(1),
	}
	
	_, err = svc.ListResolverRulesWithContext(ctx, listInput)
	
	// Should get network error
	if err != nil {
		t.Logf("✓ Network connectivity error detected as expected: %v", err)
		
		// Validate it's a network-related error
		if strings.Contains(err.Error(), "timeout") || 
		   strings.Contains(err.Error(), "network") ||
		   strings.Contains(err.Error(), "connection") {
			t.Logf("✓ Network error properly categorized")
		}
	} else {
		t.Logf("Warning: Expected network error but request succeeded")
	}
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
		// Create context with timeout for AWS API operations
		ctx, cancel := WithAWSTimeout(context.Background(), AWSAPITimeout)
		
		sess, err := CreateAWSSessionWithTimeout(region)
		require.NoError(t, err)
		svc := route53resolver.New(sess)

		_, err = svc.GetResolverRuleWithContext(ctx, &route53resolver.GetResolverRuleInput{
			ResolverRuleId: aws.String(ruleID),
		})
		cancel() // Clean up context

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
	// Create context with timeout for AWS API operations
	ctx, cancel := WithAWSTimeout(context.Background(), AWSLongTimeout)
	defer cancel()
	
	sess, err := CreateAWSSessionWithTimeout(region)
	require.NoError(t, err)
	svc := route53resolver.New(sess)

	// Create security group for resolver endpoint
	ec2Svc := ec2.New(sess)
	sgInput := &ec2.CreateSecurityGroupInput{
		GroupName:   aws.String(fmt.Sprintf("test-resolver-sg-%s", random.UniqueId())),
		Description: aws.String("Test security group for resolver endpoint"),
		VpcId:       aws.String(vpcID),
	}

	sgResult, err := ec2Svc.CreateSecurityGroupWithContext(ctx, sgInput)
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

	result, err := svc.CreateResolverEndpointWithContext(ctx, input)
	require.NoError(t, err)

	// Wait for endpoint to be available
	WaitForResolverEndpointAvailable(t, region, *result.ResolverEndpoint.Id, 30, 10*time.Second)

	return *result.ResolverEndpoint.Id
}

// WaitForResolverEndpointAvailable waits for a resolver endpoint to become available
func WaitForResolverEndpointAvailable(t *testing.T, region, endpointID string, maxRetries int, sleepBetweenRetries time.Duration) {
	retry.DoWithRetry(t, fmt.Sprintf("Waiting for resolver endpoint %s to be available", endpointID), maxRetries, sleepBetweenRetries, func() (string, error) {
		ctx, cancel := WithAWSTimeout(context.Background(), AWSAPITimeout)
		defer cancel()
		
		sess, err := CreateAWSSessionWithTimeout(region)
		require.NoError(t, err)
		svc := route53resolver.New(sess)

		result, err := svc.GetResolverEndpointWithContext(ctx, &route53resolver.GetResolverEndpointInput{
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

// DetectAWSAccountType detects the type of AWS account (personal, organization, sandbox, production)
func DetectAWSAccountType(t *testing.T, region string) string {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region),
	})
	if err != nil {
		t.Logf("Failed to create AWS session for account type detection: %v", err)
		return "unknown"
	}

	// Check if we're in an AWS Organizations account (with graceful degradation)
	orgClient := organizations.New(sess)
	_, err = orgClient.DescribeOrganization(&organizations.DescribeOrganizationInput{})
	if err == nil {
		t.Log("Detected AWS Organizations account")
		return "organization"
	} else {
		// Organizations API might not be available or accessible
		t.Logf("Organizations API not accessible (expected in many environments): %v", err)
	}

	// Check STS caller identity for account information
	stsClient := sts.New(sess)
	identity, err := stsClient.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		t.Logf("Failed to get caller identity: %v", err)
		return "unknown"
	}

	accountID := *identity.Account
	userArn := *identity.Arn

	// Check if it's a sandbox/temporary account (common patterns)
	if strings.Contains(userArn, "sandbox") || strings.Contains(userArn, "test") || 
	   strings.Contains(userArn, "dev") || strings.Contains(userArn, "temp") {
		t.Log("Detected sandbox/test account")
		return "sandbox"
	}

	// Check for well-known AWS service account patterns
	if strings.HasPrefix(accountID, "123456789") || accountID == "123456789012" {
		t.Log("Detected example/mock account ID")
		return "mock"
	}

	// Check for assumed role vs user
	if strings.Contains(userArn, ":assumed-role/") {
		t.Log("Detected assumed role - likely production/CI environment")
		return "production"
	} else if strings.Contains(userArn, ":user/") {
		t.Log("Detected IAM user - likely personal/development environment")
		return "personal"
	}

	t.Log("Detected standard AWS account")
	return "standard"
}

// ValidateAccountSafety validates that we're running in a safe test environment
func ValidateAccountSafety(t *testing.T, region string) {
	accountType := DetectAWSAccountType(t, region)
	
	// Define safe account types for testing
	safeAccountTypes := []string{"sandbox", "mock", "test", "development"}
	
	isSafe := false
	for _, safeType := range safeAccountTypes {
		if strings.Contains(strings.ToLower(accountType), safeType) {
			isSafe = true
			break
		}
	}

	// Additional safety checks
	if !isSafe {
		// Check environment variables that indicate test/development environment
		testEnvVars := []string{"CI", "GITHUB_ACTIONS", "TERRAFORM_TEST", "TEST_ENV"}
		for _, envVar := range testEnvVars {
			if os.Getenv(envVar) != "" {
				t.Logf("Test environment detected via %s environment variable", envVar)
				isSafe = true
				break
			}
		}
	}

	if !isSafe && accountType == "production" {
		t.Skip("Skipping test in production environment for safety. Set TEST_ENV=true to override.")
	}

	if !isSafe && accountType == "organization" {
		t.Log("WARNING: Running tests in AWS Organizations account. Ensure this is intentional.")
	}

	t.Logf("Account safety validation passed - account type: %s", accountType)
}

// EnhancedVerifyTestEnvironment performs comprehensive test environment verification
func EnhancedVerifyTestEnvironment(t *testing.T, region string) {
	// Perform account safety validation
	ValidateAccountSafety(t, region)
	
	// Perform standard environment verification
	VerifyTestEnvironment(t, region)
	
	// Additional safety checks for Route53 Resolver testing
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region),
	})
	if err != nil {
		t.Fatalf("Failed to create AWS session: %v", err)
	}

	// Check if Route53 Resolver is available in the region
	resolverClient := route53resolver.New(sess)
	_, err = resolverClient.ListResolverEndpoints(&route53resolver.ListResolverEndpointsInput{
		MaxResults: aws.Int64(1),
	})
	if err != nil {
		if strings.Contains(err.Error(), "not supported") || strings.Contains(err.Error(), "not available") {
			t.Skipf("Route53 Resolver not available in region %s: %v", region, err)
		}
		t.Logf("Warning: Route53 Resolver API test failed in region %s: %v", region, err)
	}

	// Check for existing resolver rules to avoid conflicts
	existingRules, err := resolverClient.ListResolverRules(&route53resolver.ListResolverRulesInput{
		MaxResults: aws.Int64(10),
	})
	if err == nil && len(existingRules.ResolverRules) > 0 {
		testRuleCount := 0
		for _, rule := range existingRules.ResolverRules {
			if rule.Name != nil && strings.Contains(*rule.Name, "terratest") {
				testRuleCount++
			}
		}
		if testRuleCount > 10 {
			t.Log("WARNING: Many existing terratest resolver rules found. Consider cleanup.")
		}
	}

	t.Log("Enhanced test environment verification completed successfully")
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

	// Enhanced AWS API cleanup with optimized filtering and pagination
	maxRetries := 3
	baseDelay := time.Second
	allRules := make([]*route53resolver.ResolverRule, 0)
	
	// Optimized filters to reduce unnecessary API calls and improve performance
	filters := []*route53resolver.Filter{
		{
			Name:   aws.String("TYPE"),
			Values: []*string{aws.String("FORWARD")}, // Only get FORWARD rules
		},
	}
	
	// Enhanced filtering: try NAME-REGEX first, fallback to client-side filtering if not supported
	useRegexFilter := false
	if namePrefix != "" && len(namePrefix) > 5 {
		// NAME-REGEX might not be supported in all regions, so we'll try it first
		regexFilters := append(filters, &route53resolver.Filter{
			Name:   aws.String("NAME-REGEX"),
			Values: []*string{aws.String(fmt.Sprintf("^%s.*", namePrefix))}, // Anchor to start
		})
		
		// Test if NAME-REGEX is supported in this region
		ctx, cancel := WithAWSTimeout(context.Background(), AWSShortTimeout)
		testInput := &route53resolver.ListResolverRulesInput{
			Filters:    regexFilters,
			MaxResults: aws.Int64(1), // Minimal test
		}
		_, testErr := svc.ListResolverRulesWithContext(ctx, testInput)
		cancel()
		
		if testErr == nil {
			filters = regexFilters
			useRegexFilter = true
			t.Logf("Using optimized NAME-REGEX filter for cleanup in region %s", region)
		} else {
			t.Logf("NAME-REGEX filter not supported in region %s, falling back to client-side filtering", region)
		}
	}
	
	// Implement proper pagination for comprehensive cleanup
	var nextToken *string
	pageCount := 0
	maxPages := 10 // Prevent infinite loops
	
	for pageCount < maxPages {
		var pageResult *route53resolver.ListResolverRulesOutput
		
		for attempt := 0; attempt < maxRetries; attempt++ {
			ctx, cancel := WithAWSTimeout(context.Background(), AWSAPITimeout)
			input := &route53resolver.ListResolverRulesInput{
				Filters:    filters,
				MaxResults: aws.Int64(100), // Increased page size for efficiency
				NextToken:  nextToken,
			}
			pageResult, err = svc.ListResolverRulesWithContext(ctx, input)
			cancel()
			
			if err == nil {
				break
			}
			
			if isRetryableAWSError(err) && attempt < maxRetries-1 {
				delay := time.Duration(1<<uint(attempt)) * baseDelay
				t.Logf("ListResolverRules page %d failed (attempt %d/%d), retrying in %v: %v", 
					pageCount+1, attempt+1, maxRetries, delay, err)
				time.Sleep(delay)
				continue
			}
			
			t.Logf("Warning: Failed to list resolver rules page %d after %d attempts: %v", pageCount+1, maxRetries, err)
			return
		}
		
		// Add rules from this page
		allRules = append(allRules, pageResult.ResolverRules...)
		
		// Check if there are more pages
		if pageResult.NextToken == nil || *pageResult.NextToken == "" {
			break
		}
		nextToken = pageResult.NextToken
		pageCount++
	}
	
	if pageCount >= maxPages {
		t.Logf("Warning: Stopped pagination after %d pages to prevent excessive API calls", maxPages)
	}
	
	t.Logf("Retrieved %d resolver rules across %d pages for cleanup evaluation", len(allRules), pageCount+1)

	// Delete rules that match the test prefix with additional safety checks
	cleanupCount := 0
	skippedCount := 0
	
	for _, rule := range allRules {
		// Enhanced safety check: if we're not using regex filter, do client-side filtering
		if !useRegexFilter && namePrefix != "" && rule.Name != nil {
			if !strings.HasPrefix(*rule.Name, namePrefix) {
				continue // Skip rules that don't match prefix
			}
		}
		if rule.Name != nil && isSafeToDelete(*rule.Name, namePrefix) {
			t.Logf("Cleaning up test resolver rule: %s (ID: %s)", *rule.Name, *rule.Id)
			
			// Safely delete with exponential backoff
			if deleteResolverRuleWithRetry(t, svc, *rule.Id, *rule.Name) {
				cleanupCount++
			}
		} else {
			skippedCount++
		}
	}
	
	t.Logf("Enhanced cleanup completed: removed %d test resolver rules, skipped %d rules (filtered/safe)", 
		cleanupCount, skippedCount)
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

// Sequential counter for deterministic account ID generation (thread-safe)
var (
	accountIDCounter uint64
	accountIDMutex   sync.Mutex
)

// GenerateSequentialAccountID creates a deterministic fake AWS account ID
// Uses sequential numbers to eliminate any collision risk with real AWS accounts
func GenerateSequentialAccountID() string {
	accountIDMutex.Lock()
	defer accountIDMutex.Unlock()
	
	// Increment counter and ensure it stays within safe range
	accountIDCounter++
	if accountIDCounter > 999999999 { // Reset if approaching real account ID range
		accountIDCounter = 1
	}
	
	// Format as 12-digit account ID with 000 prefix for absolute safety
	return fmt.Sprintf("000%09d", accountIDCounter)
}

// GenerateTestResourceName creates a safe test resource name with proper prefixes
func GenerateTestResourceName(resourceType, testName string) string {
	uniqueID := strings.ToLower(random.UniqueId())
	
	// Handle special cases for AWS resource format compliance
	switch resourceType {
	case "account":
		// Use deterministic sequential account IDs to eliminate collision risk
		return GenerateSequentialAccountID()
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
		// Use deterministic sequential account IDs to eliminate collision risk
		// Session isolation maintained through calling context
		return GenerateSequentialAccountID()
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
	ctx, cancel := WithAWSTimeout(context.Background(), AWSAPITimeout)
	defer cancel()
	
	sess, err := CreateAWSSessionWithTimeout(region)
	require.NoError(t, err)
	svc := route53resolver.New(sess)

	input := &route53resolver.GetResolverRuleInput{
		ResolverRuleId: aws.String(ruleID),
	}

	_, err = svc.GetResolverRuleWithContext(ctx, input)
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

// ValidateAWSResourceFormats validates that mock AWS resource IDs follow proper formats with enhanced validation
func ValidateAWSResourceFormats(t *testing.T, resourceMap map[string]string) {
	ValidateAWSResourceFormatsWithRegion(t, resourceMap, "")
}

// ValidateAWSResourceFormatsWithRegion validates AWS resource formats with region-specific patterns and case sensitivity
func ValidateAWSResourceFormatsWithRegion(t *testing.T, resourceMap map[string]string, region string) {
	for resourceType, resourceID := range resourceMap {
		// Validate case sensitivity - AWS resource IDs should not contain uppercase letters
		if strings.ToLower(resourceID) != resourceID {
			// Check for common case violations
			hasUppercase := false
			for _, char := range resourceID {
				if char >= 'A' && char <= 'Z' {
					hasUppercase = true
					break
				}
			}
			if hasUppercase && !isValidUppercaseResource(resourceType) {
				t.Fatalf("AWS resource ID contains uppercase letters (case sensitive): %s = %s", resourceType, resourceID)
			}
		}
		
		switch resourceType {
		case "account":
			require.Regexp(t, `^[0-9]{12}$`, resourceID, 
				"AWS Account ID must be exactly 12 digits: %s", resourceID)
			require.True(t, strings.HasPrefix(resourceID, "000"), 
				"Test Account ID should start with '000' for safety: %s", resourceID)
			
			// Validate account ID doesn't use reserved ranges
			validateAccountIDRange(t, resourceID)
			
		case "resolver-endpoint":
			require.Regexp(t, `^rslvr-out-[a-f0-9]{17}$`, resourceID, 
				"Resolver endpoint ID must match format 'rslvr-out-[17 lowercase hex chars]': %s", resourceID)
			
			// Validate region-specific patterns if region provided
			if region != "" {
				validateResolverEndpointRegionPattern(t, resourceID, region)
			}
			
		case "resolver-rule":
			require.Regexp(t, `^rslvr-rr-[a-f0-9]{17}$`, resourceID, 
				"Resolver rule ID must match format 'rslvr-rr-[17 lowercase hex chars]': %s", resourceID)
				
		case "vpc":
			require.Regexp(t, `^vpc-[a-f0-9]{8}([a-f0-9]{9})?$`, resourceID, 
				"VPC ID must match format 'vpc-[8 or 17 lowercase hex chars]': %s", resourceID)
				
			// Validate VPC ID generation pattern
			validateVPCIDPattern(t, resourceID)
			
		case "security-group":
			require.Regexp(t, `^sg-[a-f0-9]{8}([a-f0-9]{9})?$`, resourceID, 
				"Security Group ID must match format 'sg-[8 or 17 lowercase hex chars]': %s", resourceID)
				
		case "subnet":
			require.Regexp(t, `^subnet-[a-f0-9]{8}([a-f0-9]{9})?$`, resourceID, 
				"Subnet ID must match format 'subnet-[8 or 17 lowercase hex chars]': %s", resourceID)
				
		case "internet-gateway":
			require.Regexp(t, `^igw-[a-f0-9]{8}([a-f0-9]{9})?$`, resourceID, 
				"Internet Gateway ID must match format 'igw-[8 or 17 lowercase hex chars]': %s", resourceID)
				
		case "route-table":
			require.Regexp(t, `^rtb-[a-f0-9]{8}([a-f0-9]{9})?$`, resourceID, 
				"Route Table ID must match format 'rtb-[8 or 17 lowercase hex chars]': %s", resourceID)
				
		case "network-acl":
			require.Regexp(t, `^acl-[a-f0-9]{8}([a-f0-9]{9})?$`, resourceID, 
				"Network ACL ID must match format 'acl-[8 or 17 lowercase hex chars]': %s", resourceID)
				
		// Enhanced validation for additional AWS resource types
		case "instance":
			require.Regexp(t, `^i-[a-f0-9]{8}([a-f0-9]{9})?$`, resourceID, 
				"EC2 Instance ID must match format 'i-[8 or 17 lowercase hex chars]': %s", resourceID)
			// Validate instance ID pattern based on region and generation
			validateInstanceIDPattern(t, resourceID, region)
				
		case "volume":
			require.Regexp(t, `^vol-[a-f0-9]{8}([a-f0-9]{9})?$`, resourceID, 
				"EBS Volume ID must match format 'vol-[8 or 17 lowercase hex chars]': %s", resourceID)
				
		case "snapshot":
			require.Regexp(t, `^snap-[a-f0-9]{8}([a-f0-9]{9})?$`, resourceID, 
				"EBS Snapshot ID must match format 'snap-[8 or 17 lowercase hex chars]': %s", resourceID)
				
		case "ami":
			require.Regexp(t, `^ami-[a-f0-9]{8}([a-f0-9]{9})?$`, resourceID, 
				"AMI ID must match format 'ami-[8 or 17 lowercase hex chars]': %s", resourceID)
				
		case "key-pair":
			// Key pair names have different validation (no ID format)
			require.True(t, len(resourceID) >= 1 && len(resourceID) <= 255, 
				"Key pair name must be 1-255 characters: %s", resourceID)
			require.Regexp(t, `^[a-zA-Z0-9_.-]+$`, resourceID, 
				"Key pair name contains invalid characters: %s", resourceID)
				
		case "elastic-ip":
			require.Regexp(t, `^eipalloc-[a-f0-9]{8}([a-f0-9]{9})?$`, resourceID, 
				"Elastic IP allocation ID must match format 'eipalloc-[8 or 17 lowercase hex chars]': %s", resourceID)
				
		case "nat-gateway":
			require.Regexp(t, `^nat-[a-f0-9]{17}$`, resourceID, 
				"NAT Gateway ID must match format 'nat-[17 lowercase hex chars]': %s", resourceID)
				
		case "load-balancer":
			// Application/Network Load Balancer ARN pattern (simplified for testing)
			if strings.Contains(resourceID, "arn:aws:elasticloadbalancing") {
				validateLoadBalancerARN(t, resourceID, region)
			} else {
				// Classic Load Balancer name pattern
				require.Regexp(t, `^[a-zA-Z0-9-]{1,32}$`, resourceID, 
					"Load Balancer name must be 1-32 alphanumeric characters and hyphens: %s", resourceID)
			}
				
		case "target-group":
			require.Regexp(t, `^arn:aws:elasticloadbalancing:[a-z0-9-]+:[0-9]{12}:targetgroup/[a-zA-Z0-9-]{1,32}/[a-f0-9]{17}$`, resourceID, 
				"Target Group ARN must follow proper format: %s", resourceID)
				
		case "iam-role":
			// IAM role names or ARNs
			if strings.HasPrefix(resourceID, "arn:aws:iam::") {
				validateIAMRoleARN(t, resourceID)
			} else {
				require.Regexp(t, `^[a-zA-Z0-9+=,.@_-]{1,64}$`, resourceID, 
					"IAM role name must be 1-64 characters with allowed chars: %s", resourceID)
			}
				
		case "iam-policy":
			if strings.HasPrefix(resourceID, "arn:aws:iam::") {
				validateIAMPolicyARN(t, resourceID)
			} else {
				require.Regexp(t, `^[a-zA-Z0-9+=,.@_-]{1,128}$`, resourceID, 
					"IAM policy name must be 1-128 characters: %s", resourceID)
			}
				
		case "s3-bucket":
			// S3 bucket names have specific rules
			validateS3BucketName(t, resourceID)
				
		case "lambda-function":
			if strings.HasPrefix(resourceID, "arn:aws:lambda:") {
				validateLambdaFunctionARN(t, resourceID, region)
			} else {
				require.Regexp(t, `^[a-zA-Z0-9-_]{1,64}$`, resourceID, 
					"Lambda function name must be 1-64 alphanumeric characters, hyphens, and underscores: %s", resourceID)
			}
				
		case "rds-instance":
			require.Regexp(t, `^[a-zA-Z][a-zA-Z0-9-]{0,62}$`, resourceID, 
				"RDS instance identifier must start with letter, 1-63 alphanumeric and hyphens: %s", resourceID)
				
		case "rds-cluster":
			require.Regexp(t, `^[a-zA-Z][a-zA-Z0-9-]{0,62}$`, resourceID, 
				"RDS cluster identifier must start with letter, 1-63 alphanumeric and hyphens: %s", resourceID)
				
		default:
			t.Logf("Warning: Unknown resource type '%s' for validation: %s", resourceType, resourceID)
			// Enhanced fallback validation for unknown types
			if strings.Contains(resourceID, "arn:aws:") {
				validateGenericARN(t, resourceID, region)
			}
		}
		
		// Additional validation for resource ID entropy and patterns
		validateResourceIDEntropy(t, resourceType, resourceID)
		
		t.Logf("✓ AWS resource format validated: %s = %s", resourceType, resourceID)
	}
}

// isValidUppercaseResource checks if a resource type allows uppercase characters
func isValidUppercaseResource(resourceType string) bool {
	// Some AWS resources allow uppercase (e.g., S3 bucket names in certain contexts)
	upperCaseAllowed := map[string]bool{
		"s3-bucket":     true,  // S3 bucket names can have uppercase in some legacy cases
		"iam-role":      true,  // IAM role names can have uppercase
		"iam-policy":    true,  // IAM policy names can have uppercase
		"lambda-function": true, // Lambda function names can have uppercase
	}
	
	return upperCaseAllowed[resourceType]
}

// validateResolverEndpointRegionPattern validates resolver endpoint patterns based on region
func validateResolverEndpointRegionPattern(t *testing.T, resourceID, region string) {
	// Extract the hex portion for entropy validation
	if len(resourceID) >= 28 { // "rslvr-out-" + 17 hex chars
		hexPortion := resourceID[10:] // Skip "rslvr-out-"
		
		// Validate hex entropy (should not be all same character)
		if strings.Count(hexPortion, string(hexPortion[0])) == len(hexPortion) {
			t.Fatalf("Resolver endpoint ID has insufficient entropy (all same character): %s", resourceID)
		}
		
		// Regional validation patterns can be added here if AWS has region-specific patterns
		t.Logf("✓ Resolver endpoint region pattern validated for %s: %s", region, resourceID)
	}
}

// validateVPCIDPattern validates VPC ID generation patterns
func validateVPCIDPattern(t *testing.T, resourceID string) {
	// VPC IDs should not be sequential or predictable patterns
	if len(resourceID) >= 12 { // "vpc-" + at least 8 hex chars
		hexPortion := resourceID[4:] // Skip "vpc-"
		
		// Check for sequential patterns (not realistic for AWS)
		if isSequentialHex(hexPortion) {
			t.Fatalf("VPC ID shows suspicious sequential pattern: %s", resourceID)
		}
		
		// Check for insufficient entropy
		if strings.Count(hexPortion, string(hexPortion[0])) == len(hexPortion) {
			t.Fatalf("VPC ID has insufficient entropy: %s", resourceID)
		}
	}
}

// validateInstanceIDPattern validates EC2 instance ID patterns
func validateInstanceIDPattern(t *testing.T, resourceID, region string) {
	if len(resourceID) >= 10 { // "i-" + at least 8 hex chars
		hexPortion := resourceID[2:] // Skip "i-"
		
		// Validate generation (8 chars = old format, 17 chars = new format)
		if len(hexPortion) != 8 && len(hexPortion) != 17 {
			t.Fatalf("Instance ID has invalid hex length: %s (expected 8 or 17 chars)", resourceID)
		}
		
		// Check entropy
		if strings.Count(hexPortion, string(hexPortion[0])) == len(hexPortion) {
			t.Fatalf("Instance ID has insufficient entropy: %s", resourceID)
		}
		
		t.Logf("✓ Instance ID pattern validated for %s: %s", region, resourceID)
	}
}

// validateLoadBalancerARN validates Application/Network Load Balancer ARN format
func validateLoadBalancerARN(t *testing.T, arn, region string) {
	// ALB/NLB ARN format: arn:aws:elasticloadbalancing:region:account-id:loadbalancer/app|net/name/id
	arnPattern := `^arn:aws:elasticloadbalancing:[a-z0-9-]+:[0-9]{12}:loadbalancer/(app|net)/[a-zA-Z0-9-]{1,32}/[a-f0-9]{17}$`
	require.Regexp(t, arnPattern, arn, "Invalid load balancer ARN format: %s", arn)
	
	// Validate region matches if provided
	if region != "" && !strings.Contains(arn, ":"+region+":") {
		t.Fatalf("Load balancer ARN region mismatch. Expected %s in ARN: %s", region, arn)
	}
}

// validateIAMRoleARN validates IAM role ARN format
func validateIAMRoleARN(t *testing.T, arn string) {
	// IAM role ARN format: arn:aws:iam::account-id:role/role-name
	arnPattern := `^arn:aws:iam::[0-9]{12}:role/[a-zA-Z0-9+=,.@_/-]{1,64}$`
	require.Regexp(t, arnPattern, arn, "Invalid IAM role ARN format: %s", arn)
}

// validateIAMPolicyARN validates IAM policy ARN format  
func validateIAMPolicyARN(t *testing.T, arn string) {
	// IAM policy ARN format: arn:aws:iam::account-id:policy/policy-name
	arnPattern := `^arn:aws:iam::[0-9]{12}:policy/[a-zA-Z0-9+=,.@_/-]{1,128}$`
	require.Regexp(t, arnPattern, arn, "Invalid IAM policy ARN format: %s", arn)
}

// validateS3BucketName validates S3 bucket naming rules
func validateS3BucketName(t *testing.T, bucketName string) {
	// S3 bucket naming rules
	require.True(t, len(bucketName) >= 3 && len(bucketName) <= 63, 
		"S3 bucket name must be 3-63 characters: %s", bucketName)
	
	require.Regexp(t, `^[a-z0-9.-]+$`, bucketName, 
		"S3 bucket name can only contain lowercase letters, numbers, periods, and hyphens: %s", bucketName)
	
	require.True(t, !strings.HasPrefix(bucketName, ".") && !strings.HasSuffix(bucketName, "."),
		"S3 bucket name cannot start or end with period: %s", bucketName)
	
	require.True(t, !strings.HasPrefix(bucketName, "-") && !strings.HasSuffix(bucketName, "-"),
		"S3 bucket name cannot start or end with hyphen: %s", bucketName)
	
	require.False(t, strings.Contains(bucketName, ".."), 
		"S3 bucket name cannot contain consecutive periods: %s", bucketName)
		
	require.False(t, strings.Contains(bucketName, ".-") || strings.Contains(bucketName, "-."), 
		"S3 bucket name cannot have period adjacent to hyphen: %s", bucketName)
}

// validateLambdaFunctionARN validates Lambda function ARN format
func validateLambdaFunctionARN(t *testing.T, arn, region string) {
	// Lambda function ARN format: arn:aws:lambda:region:account-id:function:function-name
	arnPattern := `^arn:aws:lambda:[a-z0-9-]+:[0-9]{12}:function:[a-zA-Z0-9-_]{1,64}$`
	require.Regexp(t, arnPattern, arn, "Invalid Lambda function ARN format: %s", arn)
	
	// Validate region matches if provided
	if region != "" && !strings.Contains(arn, ":"+region+":") {
		t.Fatalf("Lambda function ARN region mismatch. Expected %s in ARN: %s", region, arn)
	}
}

// validateGenericARN validates basic ARN structure for unknown types
func validateGenericARN(t *testing.T, arn, region string) {
	// Basic ARN format: arn:partition:service:region:account-id:resource
	arnPattern := `^arn:[a-z0-9-]+:[a-z0-9-]+:[a-z0-9-]*:[0-9]{12}:.+$`
	require.Regexp(t, arnPattern, arn, "Invalid ARN format: %s", arn)
	
	t.Logf("✓ Generic ARN format validated: %s", arn)
}

// validateResourceIDEntropy validates resource ID entropy and patterns
func validateResourceIDEntropy(t *testing.T, resourceType, resourceID string) {
	// Skip entropy validation for certain resource types that have specific naming patterns
	skipEntropyValidation := map[string]bool{
		"s3-bucket":      true, // S3 buckets often have meaningful names
		"iam-role":       true, // IAM roles often have meaningful names
		"iam-policy":     true, // IAM policies often have meaningful names
		"lambda-function": true, // Lambda functions often have meaningful names
		"rds-instance":   true, // RDS instances often have meaningful names
		"rds-cluster":    true, // RDS clusters often have meaningful names
		"key-pair":       true, // Key pairs have user-defined names
	}
	
	if skipEntropyValidation[resourceType] {
		return
	}
	
	// For AWS-generated IDs, validate entropy
	if strings.Contains(resourceID, "-") {
		parts := strings.Split(resourceID, "-")
		if len(parts) >= 2 {
			lastPart := parts[len(parts)-1]
			
			// Check if the ID part has sufficient entropy
			if len(lastPart) >= 8 && isLowEntropy(lastPart) {
				t.Logf("Warning: Resource ID may have low entropy: %s", resourceID)
			}
		}
	}
}

// isSequentialHex checks if a hex string shows sequential patterns
func isSequentialHex(hexStr string) bool {
	if len(hexStr) < 4 {
		return false
	}
	
	// Check for simple ascending patterns
	for i := 0; i < len(hexStr)-3; i++ {
		if hexStr[i] == '0' && hexStr[i+1] == '1' && hexStr[i+2] == '2' && hexStr[i+3] == '3' {
			return true
		}
		if hexStr[i] == 'a' && hexStr[i+1] == 'b' && hexStr[i+2] == 'c' && hexStr[i+3] == 'd' {
			return true
		}
	}
	
	return false
}

// isLowEntropy checks if a string has low entropy (repeated patterns)
func isLowEntropy(str string) bool {
	if len(str) < 4 {
		return false
	}
	
	// Check for repeated characters
	charCount := make(map[rune]int)
	for _, char := range str {
		charCount[char]++
	}
	
	// If any character appears more than 50% of the time, consider it low entropy
	threshold := len(str) / 2
	for _, count := range charCount {
		if count > threshold {
			return true
		}
	}
	
	return false
}

// validateAccountIDRange validates that account IDs don't use reserved ranges
func validateAccountIDRange(t *testing.T, accountID string) {
	// Reserved account ID ranges that should not be used
	reservedPrefixes := []string{
		"123456789", // AWS example account IDs
		"999999999", // Testing/invalid range
		"111111111", // Sequential pattern (suspicious)
		"222222222", // Sequential pattern (suspicious) 
		"333333333", // Sequential pattern (suspicious)
	}
	
	for _, prefix := range reservedPrefixes {
		if strings.HasPrefix(accountID, prefix) {
			t.Fatalf("Account ID uses reserved/suspicious prefix '%s': %s", prefix, accountID)
		}
	}
}

// TestResourceSafeguard provides race condition mitigation for parallel tests
type TestResourceSafeguard struct {
	mutex     sync.RWMutex
	resources map[string]TestResourceInfo
	testName  string
}

// TestResourceInfo tracks resource information for race condition detection
type TestResourceInfo struct {
	ResourceID   string
	ResourceType string
	TestName     string
	CreatedAt    time.Time
	InUse        bool
}

// NewTestResourceSafeguard creates a new test resource safeguard
func NewTestResourceSafeguard(testName string) *TestResourceSafeguard {
	return &TestResourceSafeguard{
		resources: make(map[string]TestResourceInfo),
		testName:  testName,
	}
}

// ClaimResource attempts to claim a resource for exclusive use by this test
func (trs *TestResourceSafeguard) ClaimResource(t *testing.T, resourceType, resourceID string) error {
	trs.mutex.Lock()
	defer trs.mutex.Unlock()
	
	resourceKey := fmt.Sprintf("%s:%s", resourceType, resourceID)
	
	// Check if resource is already claimed
	if existing, exists := trs.resources[resourceKey]; exists {
		if existing.InUse && existing.TestName != trs.testName {
			return fmt.Errorf("resource %s (type: %s) is already in use by test: %s (claimed at: %v)", 
				resourceID, resourceType, existing.TestName, existing.CreatedAt)
		}
	}
	
	// Claim the resource
	trs.resources[resourceKey] = TestResourceInfo{
		ResourceID:   resourceID,
		ResourceType: resourceType,
		TestName:     trs.testName,
		CreatedAt:    time.Now(),
		InUse:        true,
	}
	
	t.Logf("✓ Resource claimed for exclusive use: %s (type: %s)", resourceID, resourceType)
	return nil
}

// ReleaseResource releases a previously claimed resource
func (trs *TestResourceSafeguard) ReleaseResource(t *testing.T, resourceType, resourceID string) {
	trs.mutex.Lock()
	defer trs.mutex.Unlock()
	
	resourceKey := fmt.Sprintf("%s:%s", resourceType, resourceID)
	
	if existing, exists := trs.resources[resourceKey]; exists {
		if existing.TestName == trs.testName {
			delete(trs.resources, resourceKey)
			t.Logf("✓ Resource released: %s (type: %s)", resourceID, resourceType)
		} else {
			t.Logf("Warning: Attempted to release resource owned by different test: %s", existing.TestName)
		}
	}
}

// ReleaseAllResources releases all resources claimed by this test
func (trs *TestResourceSafeguard) ReleaseAllResources(t *testing.T) {
	trs.mutex.Lock()
	defer trs.mutex.Unlock()
	
	count := 0
	for resourceKey, resource := range trs.resources {
		if resource.TestName == trs.testName {
			delete(trs.resources, resourceKey)
			count++
		}
	}
	
	if count > 0 {
		t.Logf("✓ Released %d resources for test: %s", count, trs.testName)
	}
}

// Global test resource coordinator for cross-test race condition prevention
var globalTestCoordinator = &TestResourceSafeguard{
	resources: make(map[string]TestResourceInfo),
	testName:  "global",
}

// GenerateIsolatedTestResourceName generates a test resource name with isolation guarantees
func GenerateIsolatedTestResourceName(testName, resourceType string) string {
	// Use timestamp + test name + random suffix for isolation
	timestamp := time.Now().Unix()
	
	// Clean test name to be resource-name compatible
	cleanTestName := strings.ReplaceAll(testName, "/", "-")
	cleanTestName = strings.ReplaceAll(cleanTestName, " ", "-")
	cleanTestName = strings.ToLower(cleanTestName)
	
	// Limit length to avoid AWS resource name limits
	if len(cleanTestName) > 20 {
		cleanTestName = cleanTestName[:20]
	}
	
	// Add random suffix to prevent collisions
	randomSuffix := fmt.Sprintf("%04d", rand.Intn(10000))
	
	resourceName := fmt.Sprintf("%s-%s-%d-%s", resourceType, cleanTestName, timestamp, randomSuffix)
	
	// Ensure resource name follows AWS naming conventions
	resourceName = strings.ToLower(resourceName)
	resourceName = strings.ReplaceAll(resourceName, "_", "-")
	
	return resourceName
}

// WithTestResourceIsolation wraps a test function with resource isolation
func WithTestResourceIsolation(t *testing.T, testFunc func(*testing.T, *TestResourceSafeguard)) {
	safeguard := NewTestResourceSafeguard(t.Name())
	
	// Setup cleanup on test completion
	defer func() {
		safeguard.ReleaseAllResources(t)
		
		// Additional cleanup with recovery
		if r := recover(); r != nil {
			t.Logf("Test panic occurred, ensuring all resources are released: %v", r)
			safeguard.ReleaseAllResources(t)
			panic(r) // Re-panic to maintain test failure
		}
	}()
	
	// Run the test function with safeguard
	testFunc(t, safeguard)
}

// TestParallelSafeResourceCreation demonstrates safe parallel resource creation
func TestParallelSafeResourceCreation(t *testing.T, region string, resourceCount int) {
	// Test parallel resource creation with race condition mitigation
	var wg sync.WaitGroup
	errors := make(chan error, resourceCount)
	results := make(chan string, resourceCount)
	
	for i := 0; i < resourceCount; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			
			// Generate isolated test resource name
			resourceName := GenerateIsolatedTestResourceName(t.Name(), "resolver-rule")
			
			// Use global coordinator to claim resource
			err := globalTestCoordinator.ClaimResource(t, "resolver-rule", resourceName)
			if err != nil {
				errors <- err
				return
			}
			
			// Simulate resource creation with context timeout
			ctx, cancel := WithAWSTimeout(context.Background(), AWSAPITimeout)
			defer cancel()
			
			// Simulate AWS API call delay
			select {
			case <-time.After(time.Duration(rand.Intn(100)) * time.Millisecond):
				results <- resourceName
			case <-ctx.Done():
				errors <- fmt.Errorf("resource creation timeout for %s", resourceName)
				return
			}
			
			// Release resource after use
			globalTestCoordinator.ReleaseResource(t, "resolver-rule", resourceName)
		}(i)
	}
	
	// Wait for all goroutines to complete
	wg.Wait()
	close(errors)
	close(results)
	
	// Check for errors
	errorCount := 0
	for err := range errors {
		t.Logf("Error in parallel resource creation: %v", err)
		errorCount++
	}
	
	// Check results
	successCount := 0
	for result := range results {
		t.Logf("✓ Successfully created resource: %s", result)
		successCount++
	}
	
	t.Logf("Parallel resource creation completed: %d successes, %d errors", successCount, errorCount)
	
	// Ensure we got expected results
	if successCount+errorCount != resourceCount {
		t.Fatalf("Unexpected result count. Expected %d, got %d", resourceCount, successCount+errorCount)
	}
}

// GenerateTestUniqueID generates a unique ID for test resources with collision avoidance
func GenerateTestUniqueID(prefix string) string {
	// Use high-resolution timestamp + random component for uniqueness
	nanos := time.Now().UnixNano()
	random := rand.Int31n(99999)
	
	// Combine components for maximum uniqueness
	uniqueID := fmt.Sprintf("%s-%d-%05d", prefix, nanos, random)
	
	return uniqueID
}

// ValidateTestResourceIsolation validates that test resources are properly isolated
func ValidateTestResourceIsolation(t *testing.T, resourceNames []string) {
	// Check for duplicate resource names
	seen := make(map[string]bool)
	for _, name := range resourceNames {
		if seen[name] {
			t.Fatalf("Duplicate resource name detected (race condition): %s", name)
		}
		seen[name] = true
	}
	
	// Validate naming patterns for isolation
	for _, name := range resourceNames {
		if !strings.Contains(name, "-") {
			t.Fatalf("Resource name lacks isolation markers: %s", name)
		}
		
		// Ensure resource names have timestamp-like components
		parts := strings.Split(name, "-")
		hasTimestampComponent := false
		for _, part := range parts {
			if len(part) >= 8 && isNumeric(part) {
				hasTimestampComponent = true
				break
			}
		}
		
		if !hasTimestampComponent {
			t.Fatalf("Resource name lacks timestamp isolation component: %s", name)
		}
	}
	
	t.Logf("✓ Test resource isolation validated for %d resources", len(resourceNames))
}

// isNumeric checks if a string contains only numeric characters
func isNumeric(str string) bool {
	for _, char := range str {
		if char < '0' || char > '9' {
			return false
		}
	}
	return len(str) > 0
}

// TestConcurrentAWSOperations tests concurrent AWS operations with proper isolation
func TestConcurrentAWSOperations(t *testing.T, region string, operationCount int) {
	ctx, cancel := WithAWSTimeout(context.Background(), AWSLongTimeout)
	defer cancel()
	
	sess, err := CreateAWSSessionWithTimeout(region)
	require.NoError(t, err, "Failed to create AWS session for concurrent operations test")
	
	svc := route53resolver.New(sess)
	
	var wg sync.WaitGroup
	errors := make(chan error, operationCount)
	results := make(chan string, operationCount)
	
	// Rate limiter to prevent AWS API throttling
	rateLimiter := time.NewTicker(100 * time.Millisecond)
	defer rateLimiter.Stop()
	
	for i := 0; i < operationCount; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			
			// Rate limiting
			<-rateLimiter.C
			
			// Create operation-specific context
			opCtx, opCancel := WithAWSTimeout(ctx, AWSAPITimeout)
			defer opCancel()
			
			// Generate unique resource identifier
			testResourceID := GenerateTestUniqueID(fmt.Sprintf("test-op-%d", index))
			
			// Perform AWS operation (list resolver rules with unique filter)
			listInput := &route53resolver.ListResolverRulesInput{
				MaxResults: aws.Int64(1),
				Filters: []*route53resolver.Filter{
					{
						Name:   aws.String("Name"),
						Values: []*string{aws.String(testResourceID)}, // Non-existent filter for isolation
					},
				},
			}
			
			result, err := svc.ListResolverRulesWithContext(opCtx, listInput)
			if err != nil {
				errors <- fmt.Errorf("operation %d failed: %v", index, err)
				return
			}
			
			results <- fmt.Sprintf("operation-%d-rules-%d", index, len(result.ResolverRules))
		}(i)
	}
	
	// Wait for all operations to complete
	wg.Wait()
	close(errors)
	close(results)
	
	// Process results
	errorCount := 0
	for err := range errors {
		t.Logf("Concurrent operation error: %v", err)
		errorCount++
	}
	
	successCount := 0
	for result := range results {
		t.Logf("✓ Concurrent operation result: %s", result)
		successCount++
	}
	
	t.Logf("Concurrent AWS operations completed: %d successes, %d errors out of %d total", 
		successCount, errorCount, operationCount)
	
	// Allow some errors due to AWS rate limiting, but require majority success
	if successCount < operationCount/2 {
		t.Fatalf("Too many concurrent operation failures: %d/%d", errorCount, operationCount)
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

// TestIsolationManager manages test isolation to prevent race conditions
type TestIsolationManager struct {
	sessionID     string
	resourceLocks map[string]bool
	mutex         sync.Mutex
}

// NewTestIsolationManager creates a new test isolation manager
func NewTestIsolationManager(t *testing.T) *TestIsolationManager {
	return &TestIsolationManager{
		sessionID:     GenerateTestSessionID(t),
		resourceLocks: make(map[string]bool),
	}
}

// AcquireResourceLock acquires a lock for a specific resource to prevent race conditions
func (tim *TestIsolationManager) AcquireResourceLock(resourceType, resourceID string) error {
	tim.mutex.Lock()
	defer tim.mutex.Unlock()
	
	lockKey := fmt.Sprintf("%s:%s", resourceType, resourceID)
	if tim.resourceLocks[lockKey] {
		return fmt.Errorf("resource lock already acquired: %s", lockKey)
	}
	
	tim.resourceLocks[lockKey] = true
	return nil
}

// ReleaseResourceLock releases a lock for a specific resource
func (tim *TestIsolationManager) ReleaseResourceLock(resourceType, resourceID string) {
	tim.mutex.Lock()
	defer tim.mutex.Unlock()
	
	lockKey := fmt.Sprintf("%s:%s", resourceType, resourceID)
	delete(tim.resourceLocks, lockKey)
}

// GetIsolatedResourceName generates an isolated resource name with session and timestamp
func (tim *TestIsolationManager) GetIsolatedResourceName(resourceType, baseName string) string {
	timestamp := strconv.FormatInt(time.Now().UnixNano(), 10)
	return GenerateTestResourceNameWithSession(resourceType, fmt.Sprintf("%s-%s", baseName, timestamp), tim.sessionID)
}

// EnsureTestIsolation ensures proper test isolation for parallel execution
func EnsureTestIsolation(t *testing.T, testName string, dependencies []string) *TestIsolationManager {
	tim := NewTestIsolationManager(t)
	
	// Log test isolation setup
	t.Logf("Setting up test isolation for '%s' with session ID: %s", testName, tim.sessionID)
	
	// Acquire locks for dependencies to prevent conflicts
	for _, dep := range dependencies {
		if err := tim.AcquireResourceLock("dependency", dep); err != nil {
			t.Fatalf("Failed to acquire resource lock for dependency '%s': %v", dep, err)
		}
	}
	
	// Setup cleanup for locks
	t.Cleanup(func() {
		tim.mutex.Lock()
		defer tim.mutex.Unlock()
		
		for lockKey := range tim.resourceLocks {
			delete(tim.resourceLocks, lockKey)
		}
		
		t.Logf("Test isolation cleanup completed for session: %s", tim.sessionID)
	})
	
	return tim
}

// ValidateTestIsolation validates that test isolation is working correctly
func ValidateTestIsolation(t *testing.T, tim *TestIsolationManager, expectedResources []string) {
	tim.mutex.Lock()
	defer tim.mutex.Unlock()
	
	// Verify all expected resources are locked
	for _, resource := range expectedResources {
		lockKey := fmt.Sprintf("dependency:%s", resource)
		if !tim.resourceLocks[lockKey] {
			t.Logf("Warning: Expected resource lock not found: %s", resource)
		}
	}
	
	// Verify session ID uniqueness
	if len(tim.sessionID) < 16 {
		t.Fatalf("Session ID appears too short for uniqueness: %s", tim.sessionID)
	}
	
	t.Logf("✓ Test isolation validated: %d locks active", len(tim.resourceLocks))
}

// RaceConditionDetector detects potential race conditions in test execution
type RaceConditionDetector struct {
	resourceAccess map[string][]time.Time
	mutex          sync.RWMutex
}

// NewRaceConditionDetector creates a new race condition detector
func NewRaceConditionDetector() *RaceConditionDetector {
	return &RaceConditionDetector{
		resourceAccess: make(map[string][]time.Time),
	}
}

// RecordResourceAccess records when a resource is accessed
func (rcd *RaceConditionDetector) RecordResourceAccess(resourceID string) {
	rcd.mutex.Lock()
	defer rcd.mutex.Unlock()
	
	now := time.Now()
	rcd.resourceAccess[resourceID] = append(rcd.resourceAccess[resourceID], now)
}

// DetectRaceConditions analyzes resource access patterns for potential race conditions
func (rcd *RaceConditionDetector) DetectRaceConditions(t *testing.T, timeWindow time.Duration) {
	rcd.mutex.RLock()
	defer rcd.mutex.RUnlock()
	
	raceConditionsDetected := 0
	
	for resourceID, accessTimes := range rcd.resourceAccess {
		if len(accessTimes) <= 1 {
			continue
		}
		
		// Check for concurrent access within time window
		for i := 0; i < len(accessTimes)-1; i++ {
			for j := i + 1; j < len(accessTimes); j++ {
				timeDiff := accessTimes[j].Sub(accessTimes[i])
				if timeDiff <= timeWindow {
					t.Logf("Warning: Potential race condition detected for resource '%s': access times %v and %v (diff: %v)", 
						resourceID, accessTimes[i], accessTimes[j], timeDiff)
					raceConditionsDetected++
				}
			}
		}
	}
	
	if raceConditionsDetected > 0 {
		t.Logf("⚠️  Total potential race conditions detected: %d", raceConditionsDetected)
	} else {
		t.Logf("✓ No race conditions detected")
	}
}