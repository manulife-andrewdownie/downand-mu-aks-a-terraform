application_name = "muaks-downand-dev"

admin_username = "aksadmin"
cost_center  = "6452"
location = "canadacentral"
environment = "dev"
alias = "cac"

aks_service_principal = {
    name = "SP_MUPROG_AKS_CLUSTERPRINCIPAL_NONPROD"
    object_id = "1c879ca9-792e-4fa3-ac0e-2c22aef965f8"
    client_id = "81b410f8-c973-4e52-b912-a3ab4d93f349"
    secret    = "Io_4UD3icoq6gUUM-G~.r1dNgv.ec~Q9SX"
}

aks_subnet = {
    subnet_name = "PaaS01"
    virtual_network_name = "VNET-CAC-MUProgs-NonProduction-PaaS-01"
    resource_group_name = "CAC-MUProgs-NonProduction-network"
}

domain_login = {
    name      = "SP_MUPROG_AKS_CLUSTERPRINCIPAL_NONPROD"
    object_id = "1c879ca9-792e-4fa3-ac0e-2c22aef965f8"
}

private_endpoint_subnet = {
    resource_group_name  = "CAC-MUProgs-NonProduction-network"
    virtual_network_name = "VNET-CAC-MUProgs-NonProduction-PaaS-01"
    subnet_name          = "Privateendpoints"
}