.. _whatisparaglider:

What is Paraglider?
-------------------

Paraglider is a control plane for cloud networking resources designed to simplify the tenant networking experience. 
The Paraglider Controller exposes the Paraglider API to tenants and uses public cloud APIs to manage the tenant's cloud network.

---

How is Paraglider different from other cloud networking solutions?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Some existing options for creating/managing cloud networks are (1) using the underlying cloud APIs directly or (2) using something like Terraform.
While Terraform has its benefits in being infrastructure as code, this doesn't solve the underlying problem: that we're still speaking in terms of low-level components like virtual networks, gateways, etc. 
Other options in the space like service meshes can simplify connectivity between apps at the application layer, not the network layer. 
Often approaches like this assume that someone else has set up the IP-level connectivity for you. 

---

What's a Paraglider use case?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Let's consider a very simple case: you have two applications running on different machines that should be able to send requests to one another. 
*How do you set up the network to accomplish this?*

Depending on the cloud(s) you're using, issues like whether the hosts can be in the same network for administrative reasons, whether the hosts are in the same region, or if the hosts are in different clouds, will cause the answer to vary widely.

For a specific example of the above, consider the case when these apps are in GCP and Azure. 
Assuming these apps are private, these two hosts will require setting up a VPN gateway between the networks, configuring the connection between the gateways, setting up routes, and more, depending on the exact setup. 

Paraglider provides the exact same interface for all the different cases listed above (single-network, multi-region, multi-cloud), and creates the network necessary to achieve just that higher level goal: connect the two hosts running the apps.
