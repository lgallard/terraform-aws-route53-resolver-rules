# Migration Guide: v0.3.x to v0.4.x

## 🚨 Breaking Change Alert

**Version 0.4.x introduces a breaking change** that converts from `count`-based to `for_each`-based resources. This change fixes a critical bug where the `index()` function failed when correlating resolver rules with VPC associations.

## What Changed

### The Problem (v0.3.x and earlier)
The module used `count`-based resources which caused an index correlation mismatch:
- `local.rules` had one entry per rule
- `local.vpcs_associations` was flattened with multiple entries (one per VPC per rule)
- This caused `index()` function failures when trying to correlate resources

### The Solution (v0.4.x)
- **Converted all resources from `count` to `for_each`**
- **Restructured locals to use maps instead of lists**
- **Added robust port parsing with proper error handling**
- **Improved resource correlation using consistent map keys**

## Resource Address Changes

| Resource Type | Old Address (v0.3.x) | New Address (v0.4.x) |
|---------------|---------------------|---------------------|
| Resolver Rules | `aws_route53_resolver_rule.r[0]` | `aws_route53_resolver_rule.r["domain.com."]` |
| VPC Associations | `aws_route53_resolver_rule_association.ra[0]` | `aws_route53_resolver_rule_association.ra["domain.com.-vpc-12345"]` |
| RAM Resource Shares | `aws_ram_resource_share.endpoint_share[0]` | `aws_ram_resource_share.endpoint_share["ram-name"]` |
| RAM Principal Associations | `aws_ram_principal_association.endpoint_ram_principal[0]` | `aws_ram_principal_association.endpoint_ram_principal["domain.com.-123456789012"]` |
| RAM Resource Associations | `aws_ram_resource_association.endpoint_ram_resource[0]` | `aws_ram_resource_association.endpoint_ram_resource["ram-name"]` |

## Migration Methods

### Method 1: Automatic Migration (Simple Cases)

For simple configurations with a single rule, the module includes a `moved` block that will automatically migrate your state.

**Requirements:**
- Single rule configuration
- Upgrading directly from v0.3.x to v0.4.x
- Standard configuration without complex customizations

**Steps:**
1. Update your module version to v0.4.x
2. Run `terraform plan` 
3. Terraform will automatically handle the state migration

### Method 2: Migration Script (Multiple Rules)

For configurations with multiple rules or complex setups, use the provided migration script.

**Steps:**
1. Download the migration script:
   ```bash
   curl -O https://raw.githubusercontent.com/lgallard/terraform-aws-route53-resolver-rules/v0.4.0/migrate-v0.4.sh
   chmod +x migrate-v0.4.sh
   ```

2. Run the migration script:
   ```bash
   ./migrate-v0.4.sh
   ```

3. Follow the script's guidance to generate custom migration commands

### Method 3: Manual Migration (Full Control)

For complete control over the migration process, manually run the state migration commands.

#### Step 1: Backup Your State
```bash
# For local state
cp terraform.tfstate terraform.tfstate.backup-$(date +%Y%m%d-%H%M%S)

# For remote state
terraform state pull > terraform.tfstate.backup-$(date +%Y%m%d-%H%M%S)
```

#### Step 2: Identify Current Resources
```bash
terraform state list | grep -E "(route53_resolver_rule|ram_)"
```

#### Step 3: Run Migration Commands

**Example Configuration:**
```hcl
module "dns_rules" {
  source = "lgallard/route53-resolver-rules/aws"
  version = "0.4.0"
  
  resolver_endpoint_id = "rslvr-out-12345"
  
  rules = [
    {
      rule_name   = "internal-dns"
      domain_name = "internal.company.com."
      ram_name    = "internal-dns-share"
      vpc_ids     = ["vpc-abc123", "vpc-def456"]
      ips         = ["10.0.1.10", "10.0.1.11"]
      principals  = ["123456789012"]
    }
  ]
}
```

**Migration Commands:**
```bash
# Migrate resolver rule
terraform state mv \
  'module.dns_rules.aws_route53_resolver_rule.r[0]' \
  'module.dns_rules.aws_route53_resolver_rule.r["internal.company.com."]'

# Migrate VPC associations (one per VPC)
terraform state mv \
  'module.dns_rules.aws_route53_resolver_rule_association.ra[0]' \
  'module.dns_rules.aws_route53_resolver_rule_association.ra["internal.company.com.-vpc-abc123"]'
  
terraform state mv \
  'module.dns_rules.aws_route53_resolver_rule_association.ra[1]' \
  'module.dns_rules.aws_route53_resolver_rule_association.ra["internal.company.com.-vpc-def456"]'

# Migrate RAM resources (if using cross-account sharing)
terraform state mv \
  'module.dns_rules.aws_ram_resource_share.endpoint_share[0]' \
  'module.dns_rules.aws_ram_resource_share.endpoint_share["internal-dns-share"]'

terraform state mv \
  'module.dns_rules.aws_ram_principal_association.endpoint_ram_principal[0]' \
  'module.dns_rules.aws_ram_principal_association.endpoint_ram_principal["internal.company.com.-123456789012"]'

terraform state mv \
  'module.dns_rules.aws_ram_resource_association.endpoint_ram_resource[0]' \
  'module.dns_rules.aws_ram_resource_association.endpoint_ram_resource["internal-dns-share"]'
```

#### Step 4: Verify Migration
```bash
terraform plan
```

The plan should show no changes if the migration was successful.

## Key Mapping Rules

Understanding the new key format is crucial for successful migration:

### 1. Resolver Rules Key
- **Format:** `domain_name`
- **Example:** `"internal.company.com."`
- **Note:** Must include trailing dot

### 2. VPC Association Key  
- **Format:** `"${domain_name}-${vpc_id}"`
- **Example:** `"internal.company.com.-vpc-abc123"`

### 3. RAM Resource Share Key
- **Format:** `ram_name` (from configuration)
- **Example:** `"internal-dns-share"`
- **Default:** `"r53-${domain_name}"` if ram_name not specified

### 4. RAM Principal Association Key
- **Format:** `"${domain_name}-${principal_id}"`
- **Example:** `"internal.company.com.-123456789012"`

### 5. RAM Resource Association Key
- **Format:** `ram_name` (same as resource share)
- **Example:** `"internal-dns-share"`

## Configuration Changes

No changes to your configuration are required. The module variables remain the same:

```hcl
rules = [
  {
    rule_name   = "internal-dns"          # Optional
    domain_name = "internal.company.com." # Required, must end with dot
    ram_name    = "internal-dns-share"    # Optional
    vpc_ids     = ["vpc-abc123"]          # Required
    ips         = ["10.0.1.10"]           # Required  
    principals  = ["123456789012"]        # Optional
  }
]
```

## Improved Features in v0.4.x

### 1. Enhanced Port Parsing
The new version includes robust port parsing:
```hcl
ips = [
  "192.168.1.10",      # Defaults to port 53
  "192.168.1.11:5353"  # Custom port with validation
]
```

### 2. Better Error Handling
- Type validation for port numbers
- Graceful fallback to port 53 for invalid ports
- Clear error messages for malformed configurations

### 3. Optimized Performance
- Single-pass flattening for associations
- Map-based lookups instead of index searches
- Reduced computational complexity

## Troubleshooting

### Common Issues

#### 1. "Resource already exists" errors
**Cause:** State migration was not completed
**Solution:** Complete all state mv commands before running terraform plan

#### 2. "Resource not found in state" errors  
**Cause:** Incorrect resource addresses in migration commands
**Solution:** Use `terraform state list` to verify exact addresses

#### 3. "No changes" after upgrade
**Cause:** Successful migration
**Solution:** This is expected - no infrastructure changes should occur

### Recovery Steps

If migration fails:

1. **Restore from backup:**
   ```bash
   cp terraform.tfstate.backup-YYYYMMDD-HHMMSS terraform.tfstate
   ```

2. **Verify restoration:**
   ```bash
   terraform plan
   ```

3. **Try migration again or contact support**

## Testing Your Migration

1. **In a non-production environment:**
   ```bash
   terraform plan -out=migration.tfplan
   terraform show migration.tfplan
   ```

2. **Verify no changes planned:**
   - The plan should show "No changes"
   - If changes are shown, review your migration commands

3. **Test DNS resolution:**
   ```bash
   nslookup internal.company.com 169.254.169.253
   ```

## Support

### Before Migration
- Review this guide completely
- Test in non-production environment
- Create state backups
- Document your current configuration

### During Migration
- Follow the steps exactly as documented
- Keep backups until migration is verified
- Run terraform plan after each step

### After Migration
- Verify DNS resolution works
- Monitor CloudWatch logs
- Test cross-account sharing (if used)

### Getting Help

If you encounter issues:

1. **Check the troubleshooting section above**
2. **Review the migration script output**
3. **Open an issue with:**
   - Your configuration (sanitized)
   - Error messages
   - Steps already taken
   - Terraform version

## Version Compatibility

| Module Version | Terraform Version | AWS Provider | Status |
|----------------|-------------------|--------------|---------|
| v0.4.x | >= 1.0 | >= 4.0 | ✅ Current |
| v0.3.x | >= 0.13 | >= 3.0 | ⚠️ Deprecated |
| < v0.3.0 | >= 0.12 | >= 2.0 | 🚫 Unsupported |

## Benefits of Upgrading

### 🐛 Bug Fixes
- Resolves "index() function failed" errors
- Fixes resource correlation issues
- Eliminates count-based race conditions

### 🚀 Performance Improvements  
- Faster resource processing
- Reduced memory usage
- Better plan performance

### 🔧 Enhanced Reliability
- More predictable resource addressing
- Better error messages
- Improved state consistency

### 🔮 Future-Proof
- Follows current Terraform best practices
- Compatible with newer Terraform versions
- Foundation for future enhancements