#!/bin/bash

# Migration script for terraform-aws-route53-resolver-rules v0.3.x to v0.4.x
# This script helps migrate from count-based to for_each-based resources

set -e

echo "🔄 Route53 Resolver Rules Migration Script (v0.3.x -> v0.4.x)"
echo "================================================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

# Check if terraform is available
if ! command -v terraform &> /dev/null; then
    print_error "Terraform is not installed or not in PATH"
    exit 1
fi

# Check if we're in a terraform directory
if [ ! -f "*.tf" ] && [ ! -d ".terraform" ]; then
    print_error "This doesn't appear to be a Terraform directory"
    print_info "Please run this script from your Terraform configuration directory"
    exit 1
fi

print_info "This script will help you migrate from count-based to for_each-based resources."
print_info "It will:"
print_info "  1. Back up your current state file"
print_info "  2. Generate terraform state mv commands"
print_info "  3. Show you the commands to run"
print_info ""

# Prompt for confirmation
read -p "Do you want to continue? (y/N): " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    print_info "Migration cancelled"
    exit 0
fi

# Create backup
BACKUP_FILE="terraform.tfstate.backup-$(date +%Y%m%d-%H%M%S)"
print_info "Creating backup: $BACKUP_FILE"

if [ -f "terraform.tfstate" ]; then
    cp terraform.tfstate "$BACKUP_FILE"
    print_status "State file backed up to $BACKUP_FILE"
else
    print_warning "No local state file found (you might be using remote state)"
fi

# Generate migration commands
print_info "Generating migration commands..."
echo ""

cat << 'MIGRATION_COMMANDS'
# Migration Commands for Route53 Resolver Rules Module v0.4.x

# IMPORTANT: Replace the placeholders below with your actual values

# 1. First, get your current state to understand the existing resources:
terraform state list | grep -E "(route53_resolver_rule|route53_resolver_rule_association|ram_)"

# 2. For each resolver rule, move from count[N] to domain key:
# terraform state mv 'module.your_module_name.aws_route53_resolver_rule.r[0]' 'module.your_module_name.aws_route53_resolver_rule.r["your-domain.com."]'

# 3. For each rule association, move from count[N] to domain-vpc key:
# terraform state mv 'module.your_module_name.aws_route53_resolver_rule_association.ra[0]' 'module.your_module_name.aws_route53_resolver_rule_association.ra["your-domain.com.-vpc-12345"]'

# 4. For RAM resources (if you use cross-account sharing):
# terraform state mv 'module.your_module_name.aws_ram_resource_share.endpoint_share[0]' 'module.your_module_name.aws_ram_resource_share.endpoint_share["your-ram-name"]'
# terraform state mv 'module.your_module_name.aws_ram_principal_association.endpoint_ram_principal[0]' 'module.your_module_name.aws_ram_principal_association.endpoint_ram_principal["your-domain.com.-123456789012"]'
# terraform state mv 'module.your_module_name.aws_ram_resource_association.endpoint_ram_resource[0]' 'module.your_module_name.aws_ram_resource_association.endpoint_ram_resource["your-ram-name"]'

MIGRATION_COMMANDS

print_warning "The commands above are templates. You need to:"
print_warning "  1. Replace 'your_module_name' with your actual module name"
print_warning "  2. Replace domain names with your actual domain names (with trailing dots)"
print_warning "  3. Replace VPC IDs with your actual VPC IDs"
print_warning "  4. Replace RAM names and account IDs with your actual values"
print_warning ""

print_info "To get the exact values needed:"
print_info "  1. Run: terraform state list"
print_info "  2. Look at your module configuration for domain names and VPC IDs"
print_info "  3. Note the new key format:"
print_info "     - Rules: domain_name (e.g., 'internal.company.com.')"
print_info "     - VPC associations: domain_name-vpc_id (e.g., 'internal.company.com.-vpc-12345')"
print_info "     - RAM associations: domain_name-account_id (e.g., 'internal.company.com.-123456789012')"
print_info ""

# Offer to create a custom migration script
print_info "Would you like to generate a custom migration script based on your current state?"
read -p "This requires parsing your terraform.tfvars or *.tf files (y/N): " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    print_info "Attempting to auto-generate migration commands..."
    
    # Try to find module configurations
    MODULE_CONFIGS=$(grep -r "source.*route53-resolver-rules" *.tf 2>/dev/null | head -5)
    
    if [ -n "$MODULE_CONFIGS" ]; then
        print_info "Found these module configurations:"
        echo "$MODULE_CONFIGS"
        print_info ""
        print_info "Please manually review your configuration and create the appropriate state mv commands"
    else
        print_warning "Could not automatically detect module configuration"
        print_info "Please manually review your *.tf files for the module configuration"
    fi
fi

print_info ""
print_status "Migration preparation complete!"
print_info "Next steps:"
print_info "  1. Review the migration commands above"
print_info "  2. Customize them for your specific configuration"
print_info "  3. Run the terraform state mv commands"
print_info "  4. Run terraform plan to verify the migration"
print_info "  5. If something goes wrong, restore from backup: $BACKUP_FILE"
print_info ""
print_warning "Remember: Always test in a non-production environment first!"