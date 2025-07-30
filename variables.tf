variable "resolver_endpoint_id" {
  description = "The ID of the outbound resolver endpoint that you want to use to route DNS queries to the IP addresses specified in target_ip"
  type        = string
  default     = null

  validation {
    condition = var.resolver_endpoint_id == null || can(regex("^rslvr-out-[a-zA-Z0-9]{17}$", var.resolver_endpoint_id))
    error_message = "The resolver_endpoint_id must be a valid AWS Route53 Resolver endpoint ID format (rslvr-out-xxxxxxxxxxxxxxxxx) or null."
  }
}

variable "rules" {
  default     = []
  description = "List of rules"
  type        = list(any)

  validation {
    condition = alltrue([
      for rule in var.rules : can(rule.domain_name) && can(regex("^[a-zA-Z0-9]([a-zA-Z0-9\\-]*[a-zA-Z0-9])?\\.[a-zA-Z]{2,}\\.$", rule.domain_name))
    ])
    error_message = "Each rule domain_name must be a valid fully qualified domain name ending with a dot (e.g., example.com.)."
  }

  validation {
    condition = alltrue([
      for rule in var.rules : !can(rule.ips) || rule.ips == null || alltrue([
        for ip in rule.ips : can(regex("^((25[0-5]|(2[0-4]|1\\d|[1-9]?)\\d)\\.){3}(25[0-5]|(2[0-4]|1\\d|[1-9]?)\\d)(:[1-9]\\d{0,4}|:6553[0-5]|:655[0-2]\\d|:65[0-4]\\d{2}|:6[0-4]\\d{3})?$", ip)) || can(regex("^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$|^([0-9a-fA-F]{1,4}:)*::([0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}$", ip))
      ])
    ])
    error_message = "When provided, each IP in the ips list must be a valid IPv4 address (optionally with port 1-65535) or IPv6 address."
  }

  validation {
    condition = alltrue([
      for rule in var.rules : can(rule.vpc_ids) && alltrue([
        for vpc_id in rule.vpc_ids : can(regex("^vpc-[a-f0-9]{8}([a-f0-9]{9})?$", vpc_id))
      ])
    ])
    error_message = "Each VPC ID must be a valid AWS VPC ID format (vpc-xxxxxxxx or vpc-xxxxxxxxxxxxxxxxx)."
  }

  validation {
    condition = alltrue([
      for rule in var.rules : !can(rule.principals) || rule.principals == null || alltrue([
        for principal in rule.principals : can(regex("^\\d{12}$", principal)) || can(regex("^arn:aws:organizations::[0-9]{12}:organization/o-[a-z0-9]{10,32}$", principal))
      ])
    ])
    error_message = "Each principal must be a valid 12-digit AWS account ID or AWS Organizations ARN."
  }
}

variable "tags" {
  description = "Map of tags to apply to supported resources. Each tag is a key-value pair stored as a map of strings."
  type        = map(string)
  default     = {}

  validation {
    condition = alltrue([
      for key, value in var.tags : can(regex("^[a-zA-Z0-9+\\-=._:/@\\s]*$", key)) && length(key) <= 128
    ])
    error_message = "Tag keys must be valid AWS tag keys (alphanumeric characters, spaces, and _.:/=+@- symbols) and 128 characters or less."
  }

  validation {
    condition = alltrue([
      for key, value in var.tags : can(regex("^[a-zA-Z0-9+\\-=._:/@\\s]*$", value)) && length(value) <= 256
    ])
    error_message = "Tag values must be valid AWS tag values (alphanumeric characters, spaces, and _.:/=+@- symbols) and 256 characters or less."
  }

  validation {
    condition = length(var.tags) <= 50
    error_message = "A maximum of 50 tags are allowed per resource in AWS."
  }
}
