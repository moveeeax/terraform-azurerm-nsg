terraform {
  required_version = ">= 1.5"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.0, < 6.0"
    }
  }
}

provider "azurerm" {
  features {}
}

resource "azurerm_virtual_network" "example" {
  name                = "example-vnet"
  resource_group_name = "example-rg"
  location            = "eastus"
  address_space       = ["10.0.0.0/16"]
}

resource "azurerm_subnet" "web" {
  name                 = "web"
  resource_group_name  = "example-rg"
  virtual_network_name = azurerm_virtual_network.example.name
  address_prefixes     = ["10.0.1.0/24"]
}

module "nsg" {
  source = "../.."

  name                = "example-nsg"
  resource_group_name = "example-rg"
  location            = "eastus"

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
      name                   = "allow-ssh"
      priority               = 110
      direction              = "Inbound"
      access                 = "Allow"
      protocol               = "Tcp"
      source_address_prefix  = "10.0.0.0/8"
      destination_port_range = "22"
    }
  ]

  # The key is static, so this plans even though the subnet ID is only known
  # after apply.
  subnet_ids = {
    web = azurerm_subnet.web.id
  }

  tags = {
    Environment = "sandbox"
    ManagedBy   = "terraform"
  }
}

output "nsg_id" {
  value = module.nsg.id
}
