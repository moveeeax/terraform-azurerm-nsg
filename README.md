# terraform-azurerm-nsg

Terraform module that manages an [Azure](https://azure.microsoft.com/) network
security group (NSG). Inbound and outbound security rules are supplied as a list
and rendered through a dynamic block, so any number of rules can be attached
without changing the module.

## Usage

```hcl
module "nsg" {
  source = "github.com/moveeeax/terraform-azurerm-nsg"

  name                = "web-nsg"
  resource_group_name = "prod-rg"
  location            = "eastus"

  security_rules = [
    {
      name                   = "allow-https"
      priority               = 100
      direction              = "Inbound"
      access                 = "Allow"
      protocol               = "Tcp"
      destination_port_range = "443"
    }
  ]

  tags = {
    Environment = "production"
    ManagedBy   = "terraform"
  }
}
```

A runnable example lives in [`examples/basic`](examples/basic).

## Requirements

| Name      | Version  |
|-----------|----------|
| terraform | >= 1.5   |
| azurerm   | >= 3.0   |

## Inputs

| Name                  | Description                                                            | Type           | Default | Required |
|-----------------------|------------------------------------------------------------------------|----------------|---------|:--------:|
| `name`                | Name of the network security group.                                    | `string`       | n/a     |   yes    |
| `resource_group_name` | Name of the resource group in which to create the network security group. | `string`    | n/a     |   yes    |
| `location`            | Azure region in which to create the network security group.            | `string`       | n/a     |   yes    |
| `security_rules`      | List of security rules applied to the network security group.          | `list(object)` | `[]`    |    no    |
| `tags`                | Map of tags applied to the network security group.                     | `map(string)`  | `{}`    |    no    |

## Outputs

| Name   | Description                            |
|--------|----------------------------------------|
| `id`   | ID of the network security group.      |
| `name` | Name of the network security group.    |

## License

[MIT](LICENSE)
