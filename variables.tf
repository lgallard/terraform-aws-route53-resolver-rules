variable "resolver_endpoint_id" {
  description = "The ID of the outbound resolver endpoint that you want to use to route DNS queries to the IP addresses specified in target_ip"
  type        = string
  default     = null
}

variable "rules" {
  default     = []
  description = "List of rules"
  type        = list
}

variable "tags" {
  description = "Map of tags to apply to supported resources. Each tag is a key-value pair stored as a map of strings."
  type        = map(string)
  default     = {}
}
