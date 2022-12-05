provider "azurerm" {
  features {}
}

# Configure the recommended Terraform providers and versions;
module "recommended_provider_versions" {
  source = "git@github.com:manulife-innersource/cloud-catalog.git//modules/tools/required_providers/v1?ref=stable"
}

# Define the environment variables to use in tagging the resources;
module "environment_variables" {
  source           = "git@github.com:manulife-innersource/cloud-catalog.git//modules/tools/environment_variables/v1?ref=stable"
  application_name = var.application_name
  cost_center      = var.cost_center
  environment      = var.environment
}
locals {
  resource_name_prefix = module.environment_variables.values.application_name
}

# Define the resource group;
module "resource_group" {
  source                = "git@github.com:manulife-innersource/cloud-catalog.git//modules/common/resource_group/v1?ref=stable"
  name                  = "rg-${module.environment_variables.values.application_name}"
  location              = var.location
  environment_variables = module.environment_variables.values

  role_assignments = {
    Owner = [{
      group_name   = var.domain_login.name
      principal_id = var.domain_login.object_id
    }]
  }  
}

# Lookup the ID of the AKS subnet;
module "existing_subnet" {
  source               = "git@github.com:manulife-innersource/cloud-catalog.git//modules/networking/unmanaged_subnet/v1?ref=stable"
  name                 = lookup(var.aks_subnet, "subnet_name", null)
  virtual_network_name = lookup(var.aks_subnet, "virtual_network_name", null)
  resource_group_name  = lookup(var.aks_subnet, "resource_group_name", null)
}

# Generate a private/public key pair to use to login to the linux nodes;
resource "tls_private_key" "ssh_keys" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

# Define the AKV;
module "akv" {
  source                = "git@github.com:manulife-innersource/cloud-catalog.git//modules/management_tools/key_vault/v1?ref=stable"
  name                  = "${module.environment_variables.values.application_name}-kv"
  location              = module.resource_group.location
  resource_group_name   = module.resource_group.name
  environment_variables = module.environment_variables.values
  
  key_vault_accesspolicy = [

    # Grant reader to the SPN so it can access secrets
    {
      object_id                   = var.aks_service_principal.object_id
      key_permission_role         = "administrator"
      secret_permission_role      = "administrator"
      storage_permission_role     = "administrator"
      certificate_permission_role = "administrator"
    },

    # Grant administrator to your domain login
    {
      object_id                   = var.domain_login.object_id
      key_permission_role         = "administrator"
      secret_permission_role      = "administrator"
      storage_permission_role     = "administrator"
      certificate_permission_role = "administrator"
    }
  ]

diagnostic_settings = [{
    name = "${local.resource_name_prefix}-keyvault-monitor-diagnostic"

    shared_event_hub_lookup = {
      location    = module.resource_group.location
      environment = module.environment_variables.values.environment == "prod" ? "prod" : "nonprod"
    }

    logs = [
      {
        category = "AuditEvent"
        enabled  = true

        retention_policy = {
          days    = 30
          enabled = true
        }
      },
      {
        category = "AzurePolicyEvaluationDetails"
        enabled  = true

        retention_policy = {
          days    = 30
          enabled = true
        }
      }
    ]

    metrics = [{
      category = "AllMetrics"
      enabled  = true

      retention_policy = {
        days    = 30
        enabled = true
      }
    }]
  }]

  # Store the private/public key pair for the linux nodes
  key_vault_secret = [
    {
      name  = "${module.environment_variables.values.application_name}-ssh-public-key"
      value = resource.tls_private_key.ssh_keys.public_key_openssh
    },
    {
      name  = "${module.environment_variables.values.application_name}-ssh-private-key"
      value = resource.tls_private_key.ssh_keys.private_key_openssh
    },
  ]

  # Apply a default deny to all IPs except those IPs listed in the ip_rules and virtual_network_subnet_ids
  network_acls = {
    default_action             = "Deny"                      # (Required) The Default Action to use when no rules match from ip_rules / virtual_network_subnet_ids. Possible values are Allow and Deny.
    bypass                     = "AzureServices"             # (Required) Specifies which traffic can bypass the network rules. Possible values are AzureServices and None.
    ip_rules                   = [var.allow_ip_cidr]         # (Optional) IPs or CIDRs which should be able to access this Key Vault.
    virtual_network_subnet_ids = [module.existing_subnet.id] # (Optional) One or more Subnet ID's which should be able to access this Key Vault.
  }

  role_assignments = {
    Owner = [{
      group_name   = var.domain_login.name
      principal_id = var.domain_login.object_id
    }]
  }

  private_endpoints = [{
    name                = "${local.resource_name_prefix}-${var.alias}-keyvault-endpoint"
    location            = module.resource_group.location
    resource_group_name = module.resource_group.name
    existing_subnet     = var.private_endpoint_subnet

    private_service_connections = [{
      name              = "keyvault-private-service-connection"
      subresource_names = ["vault"]
    }]

    private_dns_zone_groups = [{
      name = "manulife_core.vaultcore.azure.net"
    }]
  }]  
}

# Define the ACR;
module "acr" {
  source                        = "git@github.com:manulife-innersource/cloud-catalog.git//modules/containers/acr/v1?ref=stable"
  name                          = "${replace(module.environment_variables.values.application_name, "-", "")}registry"
  location                      = module.resource_group.location
  resource_group_name           = module.resource_group.name
  environment_variables         = module.environment_variables.values
  public_network_access_enabled = false
  sku                           = "Premium"

  # Grant access to the ACR
  network_rule_set = {
    ip_rule = [{
      action   = "Allow"
      ip_range = var.allow_ip_cidr
    }]

    virtual_network = [{
        virtual_network_name = var.aks_subnet.virtual_network_name
        subnet_name          = var.aks_subnet.subnet_name
        resource_group_name  = var.aks_subnet.resource_group_name
      }]
  }
  diagnostic_settings = [{
    name = "${local.resource_name_prefix}-acr-monitor-diagnostic"

    shared_event_hub_lookup = {
      location    = module.resource_group.location
      environment = module.environment_variables.values.environment == "prod" ? "prod" : "nonprod"
    }

    logs = [
      {
        category = "ContainerRegistryRepositoryEvents"
        enabled  = true
        retention_policy = {
          days    = 1
          enabled = true
        }
      },
      {
        category = "ContainerRegistryLoginEvents"
        enabled  = true
        retention_policy = {
          days    = 1
          enabled = true
        }
      }
    ]

    metrics = [{
      category = "AllMetrics"
      enabled  = true
      retention_policy = {
        days    = 1
        enabled = true
      }
    }]
  }]

  private_endpoints = [{
    name                = "${local.resource_name_prefix}-${var.alias}-acr-endpoint"
    location            = module.resource_group.location
    resource_group_name = module.resource_group.name
    existing_subnet     = var.private_endpoint_subnet

    private_service_connections = [{
      name              = "acr-private-service-connection"
      subresource_names = ["registry"]
    }]

    private_dns_zone_groups = [{
      name = "manulife_core.azurecr.io"
    }]
  }]

  role_assignments = {

    # Grant pull access to the SPN so it can spin up containers/workloads
    AcrPull = [{
      serviceprincipal_name = var.aks_service_principal.name
      principal_id          = var.aks_service_principal.object_id
      skip_aad_check        = false
    }]

    Owner = [{
      group_name   = var.domain_login.name
      principal_id = var.domain_login.object_id
    }]    
  }
}

# Define the AKS cluster;
module "aks" {
  source                   = "git@github.com:manulife-innersource/cloud-catalog.git//modules/containers/aks/v1?ref=stable"
  environment_variables    = module.environment_variables.values
  resource_group_name      = module.resource_group.name
  location                 = module.resource_group.location
  cluster_name             = module.environment_variables.values.application_name
  dns_prefix               = "${module.environment_variables.values.application_name}-cluster"
  private_cluster_enabled  = true
  service_principal_id     = var.aks_service_principal.client_id                  
  service_principal_secret = var.aks_service_principal.secret                     
  admin_username           = var.admin_username                                   # Name of the admin user account for logging into the linux nodes.
  ssh_public_key           = resource.tls_private_key.ssh_keys.public_key_openssh # SSH public key used to login to the linux nodes.
  private_dns_zone_id      = "manulife_core/privatelink.${module.resource_group.location}.azmk8s.io"
  existing_subnet          = var.aks_subnet

  default_node_pool = {
    name           = "default",
    node_count     = 3,
    custom_vm_size = "Standard_E4s_v3",
  }

  diagnostic_settings = [
    {
      name = "${local.resource_name_prefix}-aks-monitor-diagnostic"

      shared_event_hub_lookup = {
        location    = module.resource_group.location
        environment = module.environment_variables.values.environment == "prod" ? "prod" : "nonprod"
      }

      logs = [
        {
          category = "kube-apiserver"
          enabled  = true
          retention_policy = {
            days    = 1
            enabled = true
          }
        },
        {
          category = "kube-audit"
          enabled  = true
          retention_policy = {
            days    = 2
            enabled = true
          }
        },
        {
          category = "kube-audit-admin"
          enabled  = true
          retention_policy = {
            days    = 2
            enabled = true
          }
        },
        {
          category = "kube-controller-manager"
          enabled  = true
          retention_policy = {
            days    = 15
            enabled = true
          }
        },
        {
          category = "kube-scheduler"
          enabled  = true
          retention_policy = {
            days    = 15
            enabled = true
          }
        },
        {
          category = "cluster-autoscaler"
          enabled  = true
          retention_policy = {
            days    = 15
            enabled = true
          }
        },
        {
          category = "guard"
          enabled  = true
          retention_policy = {
            days    = 15
            enabled = true
          }
        },
      ]
      metrics = [
        {
          category = "AllMetrics"
          enabled  = true
          retention_policy = {
            days    = 10
            enabled = true
          }
      }]
  }]

  network_profile = "Basic-Kubenet"
  network = {
    service_cidr       = "172.29.4.0/24"
    dns_service_ip     = "172.29.4.10"
    pod_cidr           = "172.29.56.0/21"
    docker_bridge_cidr = "172.17.0.1/16"
    outbound_type      = "userDefinedRouting"
  }

# Exceptions to default Gatekeeper policies for k8s-catalog components
  policy_set_definition = {
    policy_definitions = {
      pod_host_network_and_port = {
        effect             = "deny",
        excludedNamespaces = ["kube-system", "gatekeeper-system", "flux-system", "observability", "akv2k8s", "cert-manager", "falco", "istio-system", "operators", "velero", "twistlock"],
        allowHostNetwork   = false,
        minPort            = 443,
        maxPort            = 443
      },
      container_host_namespace = {
        effect             = "deny",
        excludedNamespaces = ["kube-system", "gatekeeper-system", "flux-system", "observability", "akv2k8s", "cert-manager", "falco", "istio-system", "operators", "velero", "twistlock"],
      }
    }
  }
  role_assignments = {
    "Azure Kubernetes Service Contributor Role" = [{
      serviceprincipal_name = var.aks_service_principal.name
      principal_id          = var.aks_service_principal.object_id
      skip_aad_check        = false
    }]

    "Azure Kubernetes Service RBAC Reader" = [{
      group_name   = var.domain_login.name
      principal_id = var.domain_login.object_id
    }]

    Owner = [{
      group_name   = var.domain_login.name
      principal_id = var.domain_login.object_id
    }]    
  }
}