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

  validation {
    condition     = alltrue([for rule in var.security_rules : contains(["inbound", "outbound"], lower(rule.direction))])
    error_message = "Each security rule direction must be either \"Inbound\" or \"Outbound\"."
  }

  validation {
    condition     = alltrue([for rule in var.security_rules : contains(["allow", "deny"], lower(rule.access))])
    error_message = "Each security rule access must be either \"Allow\" or \"Deny\"."
  }

  validation {
    condition     = alltrue([for rule in var.security_rules : contains(["tcp", "udp", "icmp", "esp", "ah", "*"], lower(rule.protocol))])
    error_message = "Each security rule protocol must be one of Tcp, Udp, Icmp, Esp, Ah or \"*\"."
  }

  validation {
    condition     = alltrue([for rule in var.security_rules : rule.priority >= 100 && rule.priority <= 4096])
    error_message = "Each security rule priority must be between 100 and 4096; Azure reserves everything outside that range."
  }

  # Azure only accepts a single port or a single range here; comma separated
  # lists belong in destination_port_ranges, which this module does not expose.
  # Rejecting anything else at plan time also keeps the public exposure guard
  # in main.tf from being bypassed by an unparseable value.
  validation {
    condition = alltrue([
      for rule in var.security_rules : alltrue([
        can(regex("^(\\*|[0-9]{1,5}(-[0-9]{1,5})?)$", rule.source_port_range)),
        can(regex("^(\\*|[0-9]{1,5}(-[0-9]{1,5})?)$", rule.destination_port_range)),
      ])
    ])
    error_message = "Port ranges must be \"*\", a single port such as \"443\", or a range such as \"8000-8100\"."
  }
}

variable "allow_public_admin_ports" {
  description = "Allow inbound rules that expose a port in admin_ports to the internet. Left false, such a rule fails at plan time instead of quietly opening SSH, RDP or a database port to the world."
  type        = bool
  default     = false
}

variable "admin_ports" {
  description = "Ports the public exposure guard treats as administrative or database ports. Set to [] to disable the guard entirely."
  type        = list(number)
  default     = [22, 23, 135, 445, 1433, 1521, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 9200, 27017]
}

variable "tags" {
  description = "Map of tags applied to the network security group."
  type        = map(string)
  default     = {}
}

variable "subnet_ids" {
  description = "Subnets to associate the network security group with, as a map of static name to subnet ID. Keys must be known at plan time; values may come from resources created in the same apply. A subnet can have only one NSG."
  type        = map(string)
  default     = {}

  validation {
    condition     = alltrue([for id in values(var.subnet_ids) : can(regex("(?i)^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\\.Network/virtualNetworks/[^/]+/subnets/[^/]+$", id))])
    error_message = "Each subnet_ids value must be a subnet resource ID: /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Network/virtualNetworks/<vnet>/subnets/<subnet>."
  }
}

variable "network_interface_ids" {
  description = "Network interfaces to associate the network security group with, as a map of static name to NIC ID. Keys must be known at plan time; values may come from resources created in the same apply. A NIC can have only one NSG."
  type        = map(string)
  default     = {}

  validation {
    condition     = alltrue([for id in values(var.network_interface_ids) : can(regex("(?i)^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\\.Network/networkInterfaces/[^/]+$", id))])
    error_message = "Each network_interface_ids value must be a network interface resource ID: /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Network/networkInterfaces/<nic>."
  }
}
