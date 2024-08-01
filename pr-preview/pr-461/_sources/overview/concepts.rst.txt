.. _concepts:

Concepts
==========

Overview
--------------------

Paraglider takes an "endpoint-centric" view of networking: all non-networking resources should simply define their high-level networking intents and the rest should be deployed automatically -- making the network *invisible*.

Core Concepts

* **Endpoint**: Any resource in a cloud network (eg, a VM)
* **Permit List**: A list associated with an endpoint which defines the allowed traffic for that endpoint
* **Tags**: Strings associated with an endpoint or group of endpoint which can be referred to in permit lists and commands
* **Namespaces**: A Paraglider deployment controlled by a Paraglider controller separated (both in infrastructure and in control plane) from other namespaces under the same controller

Use
----

To use Paraglider, a tenant would run the Paraglider Controller and use the Paraglider API to create cloud deployments. 
This task largely consists of creating endpoints and modifying their permit lists to enable connectivity between them.
