locals {
  # Source values that mean "reachable from anywhere on the internet". Azure
  # accepts the "Internet" service tag, "*"/"any", and the IPv4/IPv6 default
  # routes. Compared lowercased because the provider is case-insensitive here.
  public_sources = ["*", "any", "internet", "0.0.0.0/0", "::/0"]

  # Split each rule's destination port range into its bounds. The
  # var.security_rules validation guarantees the value is "*", "N" or "N-M",
  # so these always parse.
  destination_port_parts = [
    for rule in var.security_rules :
    rule.destination_port_range == "*" ? ["0", "65535"] : split("-", rule.destination_port_range)
  ]

  destination_port_bounds = [
    for parts in local.destination_port_parts : [
      min(tonumber(parts[0]), tonumber(parts[length(parts) - 1])),
      max(tonumber(parts[0]), tonumber(parts[length(parts) - 1])),
    ]
  ]

  # Inbound Allow rules that expose an administrative or database port to the
  # internet. ICMP is skipped on purpose: for ICMP the port fields carry no
  # port semantics, so matching them against a port list is meaningless.
  public_admin_rules = [
    for index, rule in var.security_rules : rule.name
    if lower(rule.direction) == "inbound"
    && lower(rule.access) == "allow"
    && lower(rule.protocol) != "icmp"
    && contains(local.public_sources, lower(coalesce(rule.source_address_prefix, "*")))
    && anytrue([
      for port in var.admin_ports :
      port >= local.destination_port_bounds[index][0] && port <= local.destination_port_bounds[index][1]
    ])
  ]

  # Azure requires rule priorities to be unique per direction within an NSG.
  inbound_priorities  = [for rule in var.security_rules : rule.priority if lower(rule.direction) == "inbound"]
  outbound_priorities = [for rule in var.security_rules : rule.priority if lower(rule.direction) == "outbound"]
}

resource "azurerm_network_security_group" "this" {
  name                = var.name
  resource_group_name = var.resource_group_name
  location            = var.location

  dynamic "security_rule" {
    for_each = var.security_rules
    content {
      name                       = security_rule.value.name
      priority                   = security_rule.value.priority
      direction                  = security_rule.value.direction
      access                     = security_rule.value.access
      protocol                   = security_rule.value.protocol
      source_port_range          = security_rule.value.source_port_range
      destination_port_range     = security_rule.value.destination_port_range
      source_address_prefix      = security_rule.value.source_address_prefix
      destination_address_prefix = security_rule.value.destination_address_prefix
      description                = security_rule.value.description
    }
  }

  tags = var.tags

  lifecycle {
    precondition {
      condition = var.allow_public_admin_ports || length(local.public_admin_rules) == 0
      error_message = join("", [
        "These inbound rules let the internet reach an administrative or database port: ",
        join(", ", local.public_admin_rules),
        ". Restrict source_address_prefix to a specific CIDR or service tag, narrow ",
        "destination_port_range, or set allow_public_admin_ports = true to accept the exposure. ",
        "The guarded port list is var.admin_ports.",
      ])
    }

    precondition {
      condition = length(distinct(local.inbound_priorities)) == length(local.inbound_priorities)
      error_message = join("", [
        "Inbound rule priorities must be unique within a network security group. Priorities given: ",
        join(", ", [for priority in local.inbound_priorities : tostring(priority)]),
        ".",
      ])
    }

    precondition {
      condition = length(distinct(local.outbound_priorities)) == length(local.outbound_priorities)
      error_message = join("", [
        "Outbound rule priorities must be unique within a network security group. Priorities given: ",
        join(", ", [for priority in local.outbound_priorities : tostring(priority)]),
        ".",
      ])
    }
  }
}
