output "id" {
  description = "ID of the network security group."
  value       = azurerm_network_security_group.this.id
}

output "name" {
  description = "Name of the network security group."
  value       = azurerm_network_security_group.this.name
}

output "subnet_association_ids" {
  description = "IDs of the subnet associations created from var.subnet_ids, keyed like the input map."
  value       = { for k, a in azurerm_subnet_network_security_group_association.this : k => a.id }
}

output "network_interface_association_ids" {
  description = "IDs of the network interface associations created from var.network_interface_ids, keyed like the input map."
  value       = { for k, a in azurerm_network_interface_security_group_association.this : k => a.id }
}
