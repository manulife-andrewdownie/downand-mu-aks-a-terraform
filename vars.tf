variable "admin_username" {
  description = "Username to login to the linux nodes."
  type        = string
}

variable "aks_service_principal" {
  description = "Service principal details used to manage the AKS cluster."
  type        = any
  default = {
    name      = ""
    object_id = ""
    client_id = ""
    secret    = ""
  }
}

variable "aks_subnet" {
  description = "Existing subnet for the AKS cluster to use."
  type        = any
  default = {
    subnet_name          = ""
    virtual_network_name = ""
    resource_group_name  = ""
  }
}

variable "allow_ip_cidr" {
  description = "The IP CIDR to grant access to the resources."
  type        = string
  default     = "165.225.208.0/23"
}

variable "application_name" {
  description = "The name of the application being deployed."
  type        = string
}

variable "cost_center" {
  description = "The cost center to associate these resources with."
  type        = string
}

variable "domain_login" {
  description = "Your domain login ."
  type        = any
  default = {
    name      = ""
    object_id = ""
  }
}

variable "environment" {
  description = "Environment being provisioned ie. dev, uat, prod."
  type        = string
}

variable "location" {
  description = "Azure region to provision the resources in ie. Canada Central."
  type        = string
}