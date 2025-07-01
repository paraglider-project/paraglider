.. _whatisparaglider:

What is Paraglider?
=====================

Paraglider is a control plane for cloud networking resources designed to simplify the tenant networking experience. 
The Paraglider Controller exposes the Paraglider API to tenants and uses public cloud APIs to manage the tenant's cloud network.

How is Paraglider different from other cloud networking solutions?
--------------------------------------------------------------------

* Infrastructure as code solutions like Terraform might save you from directly invoking cloud provider APIs and allow you to use a unified language to define your network, but everything is still expressed in terms of the resources and properties supported by each cloud. You'll still assemble your network from low-level components like virtual networks, peerings, gateways, etc.
* Service meshes and other application-layer solutions can simplify managing connectivity between services at the application layer, but often assume that someone else has set up the network-level connectivity for you.
* Network-layer multicloud solutions like Aviatrix can simplify the process of creating IP-level connectivity between clouds, but still require you to work with low-level networking building blocks and do not expose a streamlined API like Paraglider.
* Paraglider also offers cloud-agnostic constructs and transparently supports multi-region and multi-cloud connectivity, meaning that you use the same constructs whether you are establishing a connection within the same cloud and the same region, or across regions and across clouds.

What's a Paraglider use case?
------------------------------------------------
Let's consider a very simple case: you have two applications running on different machines that should be able to send requests to one another. 
*How do you set up the network to accomplish this?*

Depending on the cloud(s) you're using, issues like whether the hosts can be in the same network for administrative reasons, whether the hosts are in the same region, or if the hosts are in different clouds, will cause the answer to vary widely.

For a specific example of the above, consider the case when these apps are in GCP and Azure. 
Assuming these apps are private, these two hosts will require setting up a VPN gateway between the networks, configuring the connection between the gateways, setting up routes, and more, depending on the exact setup. 

Paraglider provides the exact same interface for all the different cases listed above (single-network, multi-region, multi-cloud), and creates the network necessary to achieve just that higher level goal: connect the two hosts running the apps.
