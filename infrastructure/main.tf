terraform {
  required_version = ">= 1.5.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.90"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # Optional: remote state (uncomment to use Azure Blob backend)
  # backend "azurerm" {
  #   resource_group_name  = "rg-terraform-state"
  #   storage_account_name = "stterraformstate"
  #   container_name       = "tfstate"
  #   key                  = "fuse-control-plane.tfstate"
  # }
}

provider "azurerm" {
  features {}
}

# ── Random suffix to ensure globally unique names ──────────────────────────
resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

# ── Resource Group ─────────────────────────────────────────────────────────
resource "azurerm_resource_group" "fuse" {
  name     = var.resource_group_name
  location = var.location
  tags     = var.tags
}

# ── Azure Container Registry ───────────────────────────────────────────────
resource "azurerm_container_registry" "fuse" {
  name                = "fusecr${random_string.suffix.result}"
  resource_group_name = azurerm_resource_group.fuse.name
  location            = azurerm_resource_group.fuse.location
  sku                 = "Basic"
  admin_enabled       = false   # Use managed identity, not admin creds
  tags                = var.tags
}

# ── Log Analytics Workspace (for AKS monitoring) ───────────────────────────
resource "azurerm_log_analytics_workspace" "fuse" {
  name                = "law-fuse-${random_string.suffix.result}"
  location            = azurerm_resource_group.fuse.location
  resource_group_name = azurerm_resource_group.fuse.name
  sku                 = "PerGB2018"
  retention_in_days   = 90
  tags                = var.tags
}

# ── Azure Kubernetes Service ───────────────────────────────────────────────
resource "azurerm_kubernetes_cluster" "fuse" {
  name                = "aks-fuse-${random_string.suffix.result}"
  location            = azurerm_resource_group.fuse.location
  resource_group_name = azurerm_resource_group.fuse.name
  dns_prefix          = "fuse-${random_string.suffix.result}"
  kubernetes_version  = var.kubernetes_version

  default_node_pool {
    name                = "system"
    node_count          = var.node_count
    vm_size             = var.node_vm_size
    os_disk_size_gb     = 50
    type                = "VirtualMachineScaleSets"
    enable_auto_scaling = true
    min_count           = 1
    max_count           = var.node_max_count
    node_labels = {
      "nodepool-type" = "system"
      "environment"   = "production"
    }
  }

  # System-assigned identity — best practice for AKS
  identity {
    type = "SystemAssigned"
  }

  # Integrate with Log Analytics for audit & observability
  oms_agent {
    log_analytics_workspace_id = azurerm_log_analytics_workspace.fuse.id
  }

  network_profile {
    network_plugin = "kubenet"
    load_balancer_sku = "standard"
  }

  tags = var.tags
}

# ── Grant AKS kubelet identity pull access from ACR ───────────────────────
resource "azurerm_role_assignment" "aks_acr_pull" {
  principal_id                     = azurerm_kubernetes_cluster.fuse.kubelet_identity[0].object_id
  role_definition_name             = "AcrPull"
  scope                            = azurerm_container_registry.fuse.id
  skip_service_principal_aad_check = true
}
