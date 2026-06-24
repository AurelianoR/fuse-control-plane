variable "resource_group_name" {
  description = "Name of the Azure Resource Group"
  type        = string
  default     = "rg-fuse-production"
}

variable "location" {
  description = "Azure region"
  type        = string
  default     = "westeurope"
}

variable "kubernetes_version" {
  description = "AKS Kubernetes version"
  type        = string
  default     = "1.28"
}

variable "node_count" {
  description = "Initial node count"
  type        = number
  default     = 2
}

variable "node_max_count" {
  description = "Maximum autoscale node count"
  type        = number
  default     = 5
}

variable "node_vm_size" {
  description = "AKS node VM SKU"
  type        = string
  default     = "Standard_B2s"
}

variable "tags" {
  description = "Resource tags"
  type        = map(string)
  default = {
    environment = "production"
    project     = "fuse-control-plane"
    managed-by  = "terraform"
    owner       = "cloud-governance-team"
  }
}
