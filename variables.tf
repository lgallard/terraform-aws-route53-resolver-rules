variable "resolver_endpoint_id" {
  description = "The ID of the outbound resolver endpoint that you want to use to route DNS queries to the IP addresses that you specify using target_ip."
  type        = string
}

variable "rules" {
  default     = []
  description = "List of rules"
  type        = list(any)
}

variable "tags" {
  default     = {}
  description = "Map of tags to apply to supported resources"
  type        = map(string)
}

variable "allow_external_principals" {
  default = false
}
