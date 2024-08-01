.. _plugin_interface:

Plugin Interface
==================

This page describes the interface that the cloud plugins must implement to be compatible with the orchestrator.

.. note::
    Each cloud API is different and may not be able to implement the features described below with their current parameters. In such cases, we can discuss the best way to proceed (potentially modifying the interface itself to be more cloud-agnostic).


**rpc CreateResource(CreateResourceRequest) returns (CreateResourceResponse) {}**
-----------------------------------------------------------------------------------


Tenant-Level Description:
^^^^^^^^^^^^^^^^^^^^^^^^^^
Creates the provided resource as a Paraglider-enabled resource.The tenant should not provide any networking details in the resource description.

Implementation-Level Description:
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Creates the provided resource in the designated Paraglider virtual network so that it can be easily connected to other Paraglider resources.

Input Details:
^^^^^^^^^^^^^^^^
The ``description`` in the resource description should specify all required parameters for that cloud but the networking details of the resource. It is expected to be a JSON string that can be directly passed to the cloud API for resource creation. 
The ``name`` field in the resource description will be the name used when creating the resource. If it is specified within the resource description itself, that value will be ignored.
An example of a resource description for an Azure VM is as follows:

.. code-block:: go

    vm-a := CreateResourceRequest {
        name: "vm-a", 
        deployment: { 
            "id": "/subscriptions/sub123/resourceGroups/rg123",
            "namespace": default,
        },
        description: bytes(`{ 
                "location": "us-east",
                "properties": {
                    "hardwareProfile": {
                        "vmSize": "Standard_B1s"
                    },
                    "osProfile": {
                        "adminPassword": <password>,
                        "adminUsername": <username>,
                        "computerName": "sample-compute"
                    },
                    "storageProfile": {
                        "imageReference": {
                            "offer": "0001-com-ubuntu-minimal-jammy",
                            "publisher": "canonical",
                            "sku": "minimal-22_04-lts-gen2",
                            "version": "latest"
                        }
                    }
                }
            }`)
    }


Resources to Create:
^^^^^^^^^^^^^^^^^^^^
* The provided resource
* A permit list for the resource (implementation varies by cloud) with all traffic denied by default
* A virtual network in the region of the resource if it does not yet exist

High-Level Logic:
^^^^^^^^^^^^^^^^^^
* Check if there exists a Paraglider virtual network in the region of the new resource
* If there is not, create one

.. note:
    To get the address space for the new region and ensure that it does not overlap with others controlled by the controller, you must call `FindUnusedAddressSpace` at the frontend server, which will call `GetUsedAddressSpaces` on all registered clouds

* If the vpc/subnet are provided, the rpc should return an error
* Create the resource, ensuring it is in the Paraglider virtual network
* Create the permit list for the resource with all traffic denied by default

**rpc GetPermitList(GetPermitListRequest) returns (GetPermitListResponse) {}**
-----------------------------------------------------------------------------------

Tenant-Level Description:
^^^^^^^^^^^^^^^^^^^^^^^^^^
Get the permit list associated with the resource. 

Implementation-Level Description:
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Gets the underlying security rules for the resource and returns them as permit list objects.

Input Details:
^^^^^^^^^^^^^^^^
``resource`` contains the URI from which to get the associated permit list.

Resources to Create:
^^^^^^^^^^^^^^^^^^^^^^
* None

High-Level Logic:
^^^^^^^^^^^^^^^^^^^^^^
* Check if the resource is a valid Paraglider resource
    * This often amounts to ensuring it is in the Paraglider virtual network
* Get the security rules associated with the resource
* Return as PermitList rules

**rpc AddPermitListRules(AddPermitListRulesRequest) returns (AddPermitListRulesResponse) {}**
------------------------------------------------------------------------------------------------

Tenant-Level Description:
^^^^^^^^^^^^^^^^^^^^^^^^^^
Add provided rules to a given resource.

Implementation-Level Description:
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Add the provided rules to the underlying security rules for the resource and setup any necessary infrastructure for the connections.

Input Details:
^^^^^^^^^^^^^^^^
* ``namespace`` is the namespace of the resource
* ``resource`` is the URI of the resource to which the rules should be added
* Within the ``rules``: 
    * ``tags`` are the tag(s) of the remote endpoint(s). This can be an IP in CIDR notation or a tag (string) that can be resolved by the tag service. This field is only read by the orchestrator to resolve the tags into the target fields, though the cloud plugin may read it to store which tags were referenced (this is useful to report to the user on gets).
    * ``protocol`` is an int determined by the IANA standard.
    * ``targets`` are the resolved tags of the remote endpoint(s) in CIDR notation.
        * The source and destination of the underlying ACL rules are inferred based on the direction (ie, if it is INBOUND, then the destination is the IP of the resource the rule is being applied to and the source is the provided target(s)).
    * ``destination`` is the destination of the traffic

Resources to Create:
^^^^^^^^^^^^^^^^^^^^^^
* Per-endpoint access control list rules (implementation varies by cloud [NSG in Azure, Firewall Rules in GCP])

High-Level Logic:
^^^^^^^^^^^^^^^^^^^^^^
* Check if the resource/rules are valid
* If the given resource and the remote endpoint are in the same cloud but different virtual networks:
    * Update the security rules to allow the traffic 
    * Create the necessary connection infrastructure between the two virtual networks (ex. Vnet peering in Azure)
* If the given resource and the remote endpoint are not in the same cloud:
    * Update the security rules to allow the traffic
    * Create the necessary connection infrastructure to connection across clouds (ex. a VPN gateway)
* In all cases (including the remote and the resource are in the same virtual network):
    * Update the security rules to allow the traffic 
    
    .. note:
        This may involve creating a new rule or updating an existing rule. Rule identity is determined by the provided name.


rpc DeletePermitListRules(DeletePermitListRulesRequest) returns (DeletePermitListRulesResponse) {}
-----------------------------------------------------------------------------------------------------

Tenant-Level Description:
^^^^^^^^^^^^^^^^^^^^^^^^^^
Delete provided rules from the given resource.

Implementation-Level Description:
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Delete the provided rules from the underlying security rules for the resource.

Input Details:
^^^^^^^^^^^^^^^^
* ``namespace`` is the namespace of the resource
* ``resource`` is the URI of the resource to which the rules should be added
* ``rule_names`` are the names of the rules to be deleted

Resources to Delete:
^^^^^^^^^^^^^^^^^^^^^^
Per-endpoint access control list rules (implementation varies by cloud [NSG in Azure, Firewall Rules in GCP])

High-Level Logic:
^^^^^^^^^^^^^^^^^^^^^^
* Delete the rules from the resource (if they exist)


**rpc GetUsedAddressSpaces(GetUsedAddressSpacesRequest) returns (GetUsedAddressSpacesResponse) {}**
-----------------------------------------------------------------------------------------------------

Tenant-Level Description:
^^^^^^^^^^^^^^^^^^^^^^^^^^
This RPC should not be exposed directly to tenants.

Implementation-Level Description:
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Find all the address spaces currently used by the Paraglider deployment in a given cloud.

Input Details:
^^^^^^^^^^^^^^^^
``deployments`` is the list of Paraglider deployments in which to search for the address spaces.

Resources to Create:
^^^^^^^^^^^^^^^^^^^^^^
* None

High-Level Logic:
^^^^^^^^^^^^^^^^^^^^^^
* Get address spaces of all vnets/subnets/vpcs created by Paraglider so far in the given deployments
* Return 

rpc CreateVpnGateway(CreateVpnGatewayRequest) returns (CreateVpnGatewayResponse) {}
-----------------------------------------------------------------------------------

Tenant-Level Description:
^^^^^^^^^^^^^^^^^^^^^^^^^^
This RPC should not be exposed directly to tenants.

Implementation-Level Description:
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Creates a VPN gateway in a given cloud.

Input Details:
^^^^^^^^^^^^^^^^
* ``deployment`` is the of deployments in which to create the gateway.
* ``cloud`` is the remote cloud to connect to.
* ``bgp_peering_ip_addresses`` are the IP addresses to use for the BGP peering with the remote cloud.

Resources to Create:
^^^^^^^^^^^^^^^^^^^^^^
* VPN gateway

High-Level Logic:
^^^^^^^^^^^^^^^^^^^^^^
* Create VPN gateway along with (manually) setting up public IP addresses for the gateway tunnels

rpc GetUsedAsns(GetUsedAsnsRequest) returns (GetUsedAsnsResponse) {}
-----------------------------------------------------------------------------------

Implementation-Level Description:
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Gets all used ASNs in a given cloud.

Input Details:
^^^^^^^^^^^^^^
* ``deployments`` is a list of deployments in which to search for the ASNs

Resources to Create:
^^^^^^^^^^^^^^^^^^^^
* None

High-Level Logic:
* Get all ASNs used by Paraglider in the given deployments

rpc GetUsedBgpPeeringIpAddresses(GetUsedBgpPeeringIpAddressesRequest) returns (GetUsedBgpPeeringIpAddressesResponse) {}
-----------------------------------------------------------------------------------------------------------------------------

Implementation-Level Description:
Gets all used BGP peering IP addresses in a given cloud.

Input Details:
^^^^^^^^^^^^^^
* ``deployments`` is a list of deployments in which to search for the ASNs

Resources to Create:
^^^^^^^^^^^^^^^^^^^^
* None

High-Level Logic:
^^^^^^^^^^^^^^^^^
* Get all BGP peering IP addresses used by Paraglider in the given deployments

rpc CreateVpnConnections(CreateVpnConnectionsRequest) returns (CreateVpnConnectionsResponse) {}
-----------------------------------------------------------------------------------

Implementation-Level Description:
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Creates VPN connections between two clouds.

Input Details:
^^^^^^^^^^^^^^
* ``deployment`` is the deployment for the current cloud in which to create the VPN connection.
* ``cloud`` is the remote cloud to connect to.
* ``asn`` is the ASN to use for the BGP peering with the remote cloud.
* ``gateway_ip_addresses``: IP addresses of the VPN tunnels in remote cloud.
* ``bgp_ip_addresses``: are the IP addresses to use for the BGP peering with the remote cloud.
* ``shared_key``: pre-shared key for IPSec

Resources to Create:
^^^^^^^^^^^^^^^^^^^^
* VPN tunnels

High-Level Logic:
^^^^^^^^^^^^^^^^^
* Create VPN tunnels on current cloud to connect to the remote cloud
* Setup BGP peering between the two clouds
