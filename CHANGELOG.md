# Changelog

All notable changes to this module are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `subnet_ids` and `network_interface_ids` inputs associate the NSG with
  subnets and network interfaces through
  `azurerm_subnet_network_security_group_association` and
  `azurerm_network_interface_security_group_association`. Both are maps keyed
  by static names, so IDs created in the same apply work. Values must be full
  resource IDs. New `subnet_association_ids` and
  `network_interface_association_ids` outputs. Both inputs default to `{}`, so
  existing deployments plan the same.

## [1.1.0] - 2026-11-05

### Changed

- Bound azurerm to `>= 3.0, < 6.0`; CI also validates and tests the declared
  floor.
- CI: bump actions to their current majors, pin OpenTofu, restrict the workflow
  token to `contents: read`, add Dependabot.

## [1.0.0]

Initial release (`v0.1.0` points at the same commit).

[Unreleased]: https://github.com/moveeeax/terraform-azurerm-nsg/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/moveeeax/terraform-azurerm-nsg/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/moveeeax/terraform-azurerm-nsg/releases/tag/v1.0.0
