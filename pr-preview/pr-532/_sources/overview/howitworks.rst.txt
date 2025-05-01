.. _howitworks:

How It Works
=====================

The Paraglider Controller uses public cloud APIs to deploy networking resources (eg, VPCs, subnets, security rules, VPN gateways) as necessary to match the high-level intents specified via the Paraglider API.

Controller Design
^^^^^^^^^^^^^^^^^

.. mermaid::

    graph TB
    UR[/User Request/] --> CC[Central Controller]

    subgraph " "  
        CC[Orchestrator]  
        CC --> AP[Azure Plugin]  
        CC --> GP[GCP Plugin]  
        CC --> IP[IBM Plugin]  
    end  

    subgraph " "  
        CC --> TS[Tag Service]  
        TS[Tag Service] --> DS1[(Tag Store)]  
    end  

    subgraph " "  
        CC --> KV[KV Store Service]  
        KV[KV Store Service] --> DS2[(KV Store)]  
    end 

    AP --> AC[Azure Cloud]  
    GP --> GC[GCP Cloud]  
    IP --> IC[IBM Cloud]  

**Overview**

The Paraglider Controller consists of several microservices: a Central Controller, a Tag Service, a general-purpose KV store, and potentially multiple Cloud Plugins. Each service is described below.

**Central Controller**

The Central Controller accepts user requests and sends requests to the other microservices to complete these tasks. It is the central point of coordination for multi-service tasks.

**Tag Service**

The Tag Service is a light-weight service on top of a key-value store which stores data about the mappings between tags and the resources that reference them ("subscribers"). Subscribers must be tracked in order to push updates to permit lists when tag membership changes.

**KV Store Service**

The KV Store Service is a general-purpose key-value store that stores data for the plugins as needed. 
For example, to meet the Paraglider interface, a plugin may need to map between rule names and rule metadata that it cannot store in the cloud's rules themselves. 
The KV store can be used to close such gaps.

**Cloud Plugins**

Cloud Plugins implement the Paraglider Cloud Plugin Interface for their respective cloud. For more about the Paraglider Cloud Plugin Interface, see :ref:`plugin_interface`.
