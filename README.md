# terraform-azurerm-nsg

Terraform module that manages an [Azure](https://azure.microsoft.com/) network
security group (NSG). Inbound and outbound security rules are supplied as a list
and rendered through a dynamic block, so any number of rules can be attached
without changing the module.

## Usage

```hcl
module "nsg" {
  source = "github.com/moveeeax/terraform-azurerm-nsg?ref=v1.0.0"

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

## Public exposure guard

Every optional field of a rule defaults to `*`, so a rule that omits
`source_address_prefix` is open to the whole internet. To stop that turning into
world-reachable SSH or RDP by accident, the module fails at **plan** time when an
inbound `Allow` rule exposes an administrative or database port to the internet:

```hcl
security_rules = [
  {
    name                   = "allow-ssh"
    priority               = 100
    direction              = "Inbound"
    access                 = "Allow"
    protocol               = "Tcp"
    destination_port_range = "22"   # source_address_prefix defaults to "*"
  }
]
```

```
Error: Resource precondition failed

  These inbound rules let the internet reach an administrative or database
  port: allow-ssh. Restrict source_address_prefix to a specific CIDR or service
  tag, narrow destination_port_range, or set allow_public_admin_ports = true to
  accept the exposure.
```

Details of the check:

- A source counts as public if it is `*`, `any`, `Internet`, `0.0.0.0/0` or `::/0`.
- A rule matches if any port in `admin_ports` falls inside its
  `destination_port_range`, so `"3000-4000"` and `"*"` are caught too, not just `"3389"`.
- Only inbound `Allow` rules are checked. `Deny` rules and outbound rules pass.
- **ICMP is skipped**: for ICMP the port fields carry type and code, not ports,
  so matching them against a port list would be meaningless.
- To accept the exposure deliberately, set `allow_public_admin_ports = true`.
  To change what counts as sensitive, override `admin_ports`; setting it to `[]`
  disables the guard.

Rules are also checked for the constraints Azure itself enforces, so they fail in
`terraform plan` rather than halfway through an apply: `direction`, `access` and
`protocol` must be valid values, `priority` must be 100-4096, port ranges must be
`*` / `N` / `N-M`, and priorities must be unique within each direction.

## Managing rules: inline only

This module renders rules into the `security_rule` block of
`azurerm_network_security_group`. That attribute is `Optional` **and** `Computed`
in the provider, which has two consequences worth knowing:

- **Do not combine this module with `azurerm_network_security_rule` resources**
  pointed at the same NSG. Mixing the inline block with standalone rule resources
  produces a perpetual diff, with each side removing the other's rules on every apply.
- **Setting `security_rules = []` does not reliably delete existing rules.** A
  config that renders zero blocks leaves the attribute unset, so the value already
  in state is kept and rules added out of band can be silently adopted rather than
  removed. To remove a rule, delete its entry from the list while other entries
  remain, or destroy and recreate the NSG.

## Requirements

| Name      | Version         |
|-----------|-----------------|
| terraform | >= 1.5          |
| azurerm   | >= 3.0, < 6.0   |

CI validates and tests the module against the 3.0.0 floor and the latest azurerm
5.x release; 6.x is excluded until it has been tested.

The test suite additionally needs Terraform >= 1.7 for `mock_provider`; the
module itself does not.

## Inputs

| Name                       | Description                                                            | Type           | Default | Required |
|----------------------------|------------------------------------------------------------------------|----------------|---------|:--------:|
| `name`                     | Name of the network security group.                                    | `string`       | n/a     |   yes    |
| `resource_group_name`      | Name of the resource group in which to create the network security group. | `string`    | n/a     |   yes    |
| `location`                 | Azure region in which to create the network security group.            | `string`       | n/a     |   yes    |
| `security_rules`           | List of security rules applied to the network security group.          | `list(object)` | `[]`    |    no    |
| `allow_public_admin_ports` | Allow inbound rules that expose a port in `admin_ports` to the internet. | `bool`       | `false` |    no    |
| `admin_ports`              | Ports the public exposure guard treats as administrative or database ports. | `list(number)` | `[22, 23, 135, 445, 1433, 1521, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 9200, 27017]` | no |
| `tags`                     | Map of tags applied to the network security group.                     | `map(string)`  | `{}`    |    no    |

### `security_rules` object

| Field                        | Type     | Default | Notes                                              |
|------------------------------|----------|---------|----------------------------------------------------|
| `name`                       | `string` | n/a     | Required.                                          |
| `priority`                   | `number` | n/a     | Required, 100-4096, unique within a direction.     |
| `direction`                  | `string` | n/a     | Required, `Inbound` or `Outbound`.                 |
| `access`                     | `string` | n/a     | Required, `Allow` or `Deny`.                       |
| `protocol`                   | `string` | n/a     | Required, one of `Tcp`, `Udp`, `Icmp`, `Esp`, `Ah`, `*`. |
| `source_port_range`          | `string` | `"*"`   | `*`, `N`, or `N-M`.                                |
| `destination_port_range`     | `string` | `"*"`   | `*`, `N`, or `N-M`.                                |
| `source_address_prefix`      | `string` | `"*"`   | CIDR or service tag. `*` means the whole internet. |
| `destination_address_prefix` | `string` | `"*"`   | CIDR or service tag.                               |
| `description`                | `string` | `null`  |                                                    |

## Outputs

| Name   | Description                            |
|--------|----------------------------------------|
| `id`   | ID of the network security group.      |
| `name` | Name of the network security group.    |

## Tests

The suite in [`tests/`](tests) runs against a mocked provider, so it needs no
Azure credentials and no network:

```
terraform init -backend=false
terraform test
```

## License

[MIT](LICENSE)
