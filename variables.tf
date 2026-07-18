variable "name" {
  description = "Name of the network security group."
  type        = string
}

variable "resource_group_name" {
  description = "Name of the resource group in which to create the network security group."
  type        = string
}

variable "location" {
  description = "Azure region in which to create the network security group."
  type        = string
}

variable "security_rules" {
  description = "List of security rules applied to the network security group."
  type = list(object({
    name                       = string
    priority                   = number
    direction                  = string
    access                     = string
    protocol                   = string
    source_port_range          = optional(string, "*")
    destination_port_range     = optional(string, "*")
    source_address_prefix      = optional(string, "*")
    destination_address_prefix = optional(string, "*")
    description                = optional(string, null)
  }))
  default = []
}

variable "tags" {
  description = "Map of tags applied to the network security group."
  type        = map(string)
  default     = {}
}
