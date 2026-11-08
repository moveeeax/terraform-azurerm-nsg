# Runs offline against a mocked provider: no Azure credentials, no network.
# mock_provider requires Terraform >= 1.7 / OpenTofu >= 1.7. That is a
# test-only requirement and deliberately not reflected in required_version,
# which stays at >= 1.5 for consumers of the module.
mock_provider "azurerm" {
  # The association resources parse network_security_group_id as an ARM ID
  # during plan, so the mocked NSG needs a well-formed ID.
  mock_resource "azurerm_network_security_group" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/test-nsg"
    }
  }
}

variables {
  name                = "test-nsg"
  resource_group_name = "test-rg"
  location            = "eastus"
}

# Must stay the first apply in this file: run blocks share one state, and
# security_rule is Optional+Computed, so a later run cannot assert on an empty
# rule set -- see the "Managing rules: inline only" caveat in README.md.
run "no_rules_by_default" {
  assert {
    condition     = length(azurerm_network_security_group.this.security_rule) == 0
    error_message = "The module must not add any security rule of its own."
  }

  assert {
    condition     = length(azurerm_subnet_network_security_group_association.this) == 0 && length(azurerm_network_interface_security_group_association.this) == 0
    error_message = "No associations may be created unless subnet_ids or network_interface_ids is set."
  }

  assert {
    condition     = output.subnet_association_ids == {} && output.network_interface_association_ids == {}
    error_message = "The association outputs must be empty by default."
  }
}

run "rules_render_into_the_nsg" {
  variables {
    security_rules = [
      {
        name                   = "allow-https"
        priority               = 100
        direction              = "Inbound"
        access                 = "Allow"
        protocol               = "Tcp"
        destination_port_range = "443"
      },
      {
        name                   = "allow-ssh-from-vnet"
        priority               = 110
        direction              = "Inbound"
        access                 = "Allow"
        protocol               = "Tcp"
        source_address_prefix  = "10.0.0.0/8"
        destination_port_range = "22"
      },
    ]
  }

  assert {
    condition     = length(azurerm_network_security_group.this.security_rule) == 2
    error_message = "Both supplied rules should be rendered onto the network security group."
  }

  assert {
    condition     = length(local.public_admin_rules) == 0
    error_message = "Public HTTPS and VNet-scoped SSH must not be flagged as public admin exposure."
  }
}

# --- public exposure guard -------------------------------------------------

run "rejects_ssh_from_wildcard_source" {
  command = plan

  variables {
    security_rules = [{
      name                   = "allow-ssh"
      priority               = 100
      direction              = "Inbound"
      access                 = "Allow"
      protocol               = "Tcp"
      destination_port_range = "22"
    }]
  }

  expect_failures = [azurerm_network_security_group.this]
}

run "rejects_rdp_from_internet_service_tag" {
  command = plan

  variables {
    security_rules = [{
      name                   = "allow-rdp"
      priority               = 100
      direction              = "Inbound"
      access                 = "Allow"
      protocol               = "Tcp"
      source_address_prefix  = "Internet"
      destination_port_range = "3389"
    }]
  }

  expect_failures = [azurerm_network_security_group.this]
}

run "rejects_admin_port_hidden_inside_a_range" {
  command = plan

  variables {
    security_rules = [{
      name                   = "allow-app-ports"
      priority               = 100
      direction              = "Inbound"
      access                 = "Allow"
      protocol               = "Tcp"
      source_address_prefix  = "0.0.0.0/0"
      destination_port_range = "3000-4000"
    }]
  }

  expect_failures = [azurerm_network_security_group.this]
}

run "rejects_allow_any_port_from_anywhere" {
  command = plan

  variables {
    security_rules = [{
      name                  = "allow-all"
      priority              = 100
      direction             = "Inbound"
      access                = "Allow"
      protocol              = "*"
      source_address_prefix = "*"
    }]
  }

  expect_failures = [azurerm_network_security_group.this]
}

run "allows_public_ssh_when_explicitly_opted_in" {
  variables {
    allow_public_admin_ports = true
    security_rules = [{
      name                   = "allow-ssh"
      priority               = 100
      direction              = "Inbound"
      access                 = "Allow"
      protocol               = "Tcp"
      source_address_prefix  = "*"
      destination_port_range = "22"
    }]
  }

  assert {
    condition     = length(azurerm_network_security_group.this.security_rule) == 1
    error_message = "Opting in must let the rule through."
  }
}

run "guard_ignores_deny_and_outbound_rules" {
  variables {
    security_rules = [
      {
        name                   = "deny-ssh"
        priority               = 100
        direction              = "Inbound"
        access                 = "Deny"
        protocol               = "Tcp"
        destination_port_range = "22"
      },
      {
        name                   = "allow-outbound-ssh"
        priority               = 100
        direction              = "Outbound"
        access                 = "Allow"
        protocol               = "Tcp"
        destination_port_range = "22"
      },
    ]
  }

  assert {
    condition     = length(local.public_admin_rules) == 0
    error_message = "A Deny rule and an outbound rule are not inbound public exposure."
  }
}

# For ICMP the port fields are type and code, not ports, so the guard must not
# match them against the admin port list.
run "guard_skips_icmp" {
  variables {
    security_rules = [{
      name                   = "allow-ping"
      priority               = 100
      direction              = "Inbound"
      access                 = "Allow"
      protocol               = "Icmp"
      source_address_prefix  = "*"
      destination_port_range = "*"
    }]
  }

  assert {
    condition     = length(local.public_admin_rules) == 0
    error_message = "ICMP has no ports, so it must never trip the admin port guard."
  }
}

run "guard_can_be_disabled_with_an_empty_port_list" {
  variables {
    admin_ports = []
    security_rules = [{
      name                   = "allow-ssh"
      priority               = 100
      direction              = "Inbound"
      access                 = "Allow"
      protocol               = "Tcp"
      source_address_prefix  = "*"
      destination_port_range = "22"
    }]
  }

  assert {
    condition     = length(local.public_admin_rules) == 0
    error_message = "An empty admin_ports list must disable the guard."
  }
}

# --- priority collisions ---------------------------------------------------

run "rejects_duplicate_inbound_priority" {
  command = plan

  variables {
    security_rules = [
      {
        name                   = "allow-https"
        priority               = 100
        direction              = "Inbound"
        access                 = "Allow"
        protocol               = "Tcp"
        destination_port_range = "443"
      },
      {
        name                   = "allow-http"
        priority               = 100
        direction              = "Inbound"
        access                 = "Allow"
        protocol               = "Tcp"
        destination_port_range = "80"
      },
    ]
  }

  expect_failures = [azurerm_network_security_group.this]
}

run "allows_the_same_priority_in_opposite_directions" {
  variables {
    security_rules = [
      {
        name                   = "allow-https-in"
        priority               = 100
        direction              = "Inbound"
        access                 = "Allow"
        protocol               = "Tcp"
        destination_port_range = "443"
      },
      {
        name                   = "allow-https-out"
        priority               = 100
        direction              = "Outbound"
        access                 = "Allow"
        protocol               = "Tcp"
        destination_port_range = "443"
      },
    ]
  }

  assert {
    condition     = length(azurerm_network_security_group.this.security_rule) == 2
    error_message = "Priorities only need to be unique within a direction."
  }
}

# --- input validation ------------------------------------------------------

run "rejects_invalid_direction" {
  command = plan

  variables {
    security_rules = [{
      name                   = "bad-direction"
      priority               = 100
      direction              = "Sideways"
      access                 = "Allow"
      protocol               = "Tcp"
      destination_port_range = "443"
    }]
  }

  expect_failures = [var.security_rules]
}

run "rejects_invalid_access" {
  command = plan

  variables {
    security_rules = [{
      name                   = "bad-access"
      priority               = 100
      direction              = "Inbound"
      access                 = "Permit"
      protocol               = "Tcp"
      destination_port_range = "443"
    }]
  }

  expect_failures = [var.security_rules]
}

run "rejects_invalid_protocol" {
  command = plan

  variables {
    security_rules = [{
      name                   = "bad-protocol"
      priority               = 100
      direction              = "Inbound"
      access                 = "Allow"
      protocol               = "Sctp"
      destination_port_range = "443"
    }]
  }

  expect_failures = [var.security_rules]
}

run "rejects_out_of_range_priority" {
  command = plan

  variables {
    security_rules = [{
      name                   = "too-low"
      priority               = 50
      direction              = "Inbound"
      access                 = "Allow"
      protocol               = "Tcp"
      destination_port_range = "443"
    }]
  }

  expect_failures = [var.security_rules]
}

run "rejects_comma_separated_port_list" {
  command = plan

  variables {
    security_rules = [{
      name                   = "bad-ports"
      priority               = 100
      direction              = "Inbound"
      access                 = "Allow"
      protocol               = "Tcp"
      source_address_prefix  = "10.0.0.0/8"
      destination_port_range = "22,3389"
    }]
  }

  expect_failures = [var.security_rules]
}

# --- associations ----------------------------------------------------------

run "associates_subnets_and_nics" {
  variables {
    subnet_ids = {
      web = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/test-rg/providers/Microsoft.Network/virtualNetworks/test-vnet/subnets/web"
      app = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/test-rg/providers/Microsoft.Network/virtualNetworks/test-vnet/subnets/app"
    }
    network_interface_ids = {
      bastion = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/test-rg/providers/Microsoft.Network/networkInterfaces/bastion-nic"
    }
  }

  assert {
    condition     = length(azurerm_subnet_network_security_group_association.this) == 2
    error_message = "One subnet association must be created per subnet_ids entry."
  }

  assert {
    condition     = azurerm_subnet_network_security_group_association.this["web"].subnet_id == var.subnet_ids["web"]
    error_message = "The subnet ID must be passed through unchanged."
  }

  assert {
    condition     = azurerm_subnet_network_security_group_association.this["app"].network_security_group_id == azurerm_network_security_group.this.id
    error_message = "Subnet associations must point at this module's NSG."
  }

  assert {
    condition     = azurerm_network_interface_security_group_association.this["bastion"].network_interface_id == var.network_interface_ids["bastion"]
    error_message = "The NIC ID must be passed through unchanged."
  }

  assert {
    condition     = azurerm_network_interface_security_group_association.this["bastion"].network_security_group_id == azurerm_network_security_group.this.id
    error_message = "NIC associations must point at this module's NSG."
  }

  assert {
    condition     = keys(output.subnet_association_ids) == ["app", "web"] && keys(output.network_interface_association_ids) == ["bastion"]
    error_message = "The association outputs must be keyed like the input maps."
  }
}

run "rejects_subnet_name_instead_of_id" {
  command = plan

  variables {
    subnet_ids = {
      web = "web-subnet"
    }
  }

  expect_failures = [var.subnet_ids]
}

run "rejects_nic_name_instead_of_id" {
  command = plan

  variables {
    network_interface_ids = {
      bastion = "bastion-nic"
    }
  }

  expect_failures = [var.network_interface_ids]
}
