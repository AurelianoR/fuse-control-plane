output "resource_group_name" {
  description = "The resource group where Fuse resources are deployed"
  value       = azurerm_resource_group.fuse.name
}

output "acr_login_server" {
  description = "Container Registry login server (use to push Docker images)"
  value       = azurerm_container_registry.fuse.login_server
}

output "aks_cluster_name" {
  description = "AKS cluster name"
  value       = azurerm_kubernetes_cluster.fuse.name
}

output "aks_get_credentials_cmd" {
  description = "Command to configure kubectl for this cluster"
  value       = "az aks get-credentials --resource-group ${azurerm_resource_group.fuse.name} --name ${azurerm_kubernetes_cluster.fuse.name}"
}

output "log_analytics_workspace_id" {
  description = "Log Analytics workspace ID for audit queries"
  value       = azurerm_log_analytics_workspace.fuse.id
}
