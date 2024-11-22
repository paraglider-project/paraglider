.. _api:

API
===

Namespace Operations
--------------------
Interact with the namespaces on the Paraglider Controller. 
The active namespace is a client-side CLI construct. 
All REST requests to the controller will be scoped on a namespace.

Set
^^^

.. tab-set::

    .. tab-item:: CLI
        :sync: cli

        .. code-block:: shell

            glide namespace set <namespace>

        Parameters:

        * ``namespace``: namespace to set on the controller


Get
^^^

Gets the current active namespace in the CLI (Note: this is only a CLI feature).

.. tab-set::

    .. tab-item:: CLI
        :sync: cli

        .. code-block:: shell

            glide namespace get

List
^^^^

Lists all namespaces configured on the controller.

.. tab-set::

    .. tab-item:: CLI
        :sync: cli

        .. code-block:: shell

            glide namespace list

    .. tab-item:: REST
        :sync: rest

        .. code-block:: shell

            GET /namespaces/


Resource Operations
-------------------

Create
^^^^^^

Creates a resource according to the description provided in the specified cloud. 
Note that a tag is automatically created for the resource with the name ``<namespace>.<cloud>.<name>`` (where ``name`` is the resource name provided -- i.e., names inside the json description of the resource will be ignored).

.. tab-set::

    .. tab-item:: CLI
        :sync: cli

        .. code-block:: shell
            
            glide resource create <cloud> <resource_name> <path_to_json>

        Parameters:

        * ``cloud``: name of the cloud to create the resource in
        * ``resource_name`` : name of the resource to be created in the Paraglider controller (note: this name will be scoped on cloud and namespace when stored)
        * ``path_to_json``: path to JSON file describing the resource to be created (excluding networking details)


    .. tab-item:: REST
        :sync: rest

        .. tab-set::

            .. tab-item:: POST

                .. code-block:: shell

                    POST /namespaces/{namespace}/clouds/{cloud}/resources

                * Example request body:

                .. code-block:: JSON

                    {
                        "name": "resourceName",
                        "description": "{
                                    \"location\": \"eastus\",
                                    \"properties\": {
                                        \"hardwareProfile\": {
                                            \"vmSize\": \"Standard_B1s\"
                                        },
                                        \"osProfile\": {
                                            \"adminPassword\": \"\",
                                            \"adminUsername\": \"\",
                                            \"computerName\": \"sample-compute\"
                                        },
                                        \"storageProfile\": {
                                            \"imageReference\": {
                                                \"offer\": \"0001-com-ubuntu-minimal-jammy\",
                                                \"publisher\": \"canonical\",
                                                \"sku\": \"minimal-22_04-lts-gen2\",
                                                \"version\": \"latest\"
                                            }
                                        }
                                    }
                                }"
                    }

                Parameters:

                * ``namespace``: Paraglider namespace to operate in
                * ``cloud``: name of the cloud to create the resource in
                * ``name`` : name of the resource to be created in the Paraglider controller (note: this name will be scoped on cloud and namespace when stored)
                * ``description``: JSON string describing the resource to be created (excluding networking details)

            .. tab-item:: PUT

                .. code-block:: shell
                    
                    PUT /namespaces/{namespace}/clouds/{cloud}/resources/{resourceName}

                * Example request body:

                .. code-block:: JSON
                        
                    {
                    "description": "{
                                    \"location\": \"eastus\",
                                    \"properties\": {
                                        \"hardwareProfile\": {
                                            \"vmSize\": \"Standard_B1s\"
                                        },
                                        \"osProfile\": {
                                            \"adminPassword\": \"\",
                                            \"adminUsername\": \"\",
                                            \"computerName\": \"sample-compute\"
                                        },
                                        \"storageProfile\": {
                                            \"imageReference\": {
                                                \"offer\": \"0001-com-ubuntu-minimal-jammy\",
                                                \"publisher\": \"canonical\",
                                                \"sku\": \"minimal-22_04-lts-gen2\",
                                                \"version\": \"latest\"
                                            }
                                        }
                                    }
                                }"
                    }

                Parameters:

                * ``namespace``: Paraglider namespace to operate in
                * ``cloud``: name of the cloud to create the resource in
                * ``resource_name`` : name of the resource to be created in the Paraglider controller (note: this name will be scoped on cloud and namespace when stored)
                * ``description``: JSON string describing the resource to be created (excluding networking details)

Attach
^^^^^^

Attaches an exisiting resource to Paraglider according to the resource ID and the specified cloud. The resource should exist within a deployment associated with a namespace in Paraglider.

Note that a tag is automatically created for the resource with the name ``<namespace>.<cloud>.<name>`` after attachment (where ``name`` is the resource name).

.. note::

    Attach Resource is only supported for Azure currently. Support for other cloud plugins are under active development.
    
.. tab-set::

    .. tab-item:: CLI
        :sync: cli

        .. code-block:: shell
            
            glide resource attach <cloud> <resource_id>

        Parameters:

        * ``cloud``: name of the cloud to create the resource in
        * ``resource_id`` : Id of the resource as specified by the cloud provider


    .. tab-item:: REST
        :sync: rest

        .. tab-set::

            .. tab-item:: POST

                .. code-block:: shell

                    POST /namespaces/{namespace}/clouds/{cloud}/resources

                * Example request body:

                .. code-block:: JSON

                    {
                        "id": "resource-id"
                    }

                Parameters:

                * ``id``: Id of the resource as specified by the cloud provider
    
.. note::
    
    Create resource and Attach resource share the same API endpoint. The difference between the two POST requests is the request body. If the request body contains a ``description``, the request is considered as a create resource request. Otherwise, it is considered as an attach resource request. 


Resource Descriptions
~~~~~~~~~~~~~~~~~~~~~~~~~
For creating resources, the description provided should generally include all fields required to create the resource in the cloud, with the exception of networking details. 
For example, a VM description should exclude the fields definiting the network interface, the subnet, etc.
When attaching a service to the Paraglider deployment, the information required to find the correct service varies by cloud.

.. tab-set::

    .. tab-item:: GCP

        The fields required for the description depend on the service. For third-party services `exposed via a service attachment <https://cloud.google.com/vpc/docs/private-service-connect#:~:text=Service%20attachments,Cloud%20DNS%20zone.>`_,  the description must be of the form:

        .. code-block:: JSON

            { 
                "url": "<service attachment URI>"
            }


        For Google services, the description must include the API bundle name `API bundle name <https://cloud.google.com/vpc/docs/about-accessing-google-apis-endpoints#supported-apis>`_ and the region in which Paraglider should connect to the services.

        .. code-block:: JSON

            {
                "api_bundle": "<api_bundle_name>",
                "region": "<region>"
            }

Permit List Operations
----------------------

These operations interact with the permit list associated with a given resource by adding/deleting/getting rules.

Get
^^^

Gets the rules associated with a resource.

.. tab-set::

    .. tab-item:: CLI
        :sync: cli

        .. code-block:: shell
            
            glide rule get <cloud> <resource_name>

        Parameters:

        * ``cloud``: name of the cloud that the resource is in
        * ``resource_name``: Paraglider name of the resource

    .. tab-item:: REST
        :sync: rest

        .. code-block:: shell

            GET /namespaces/{namespace}/clouds/{cloud}/resources/{resourceName}/rules

        Parameters:

        * ``namespace``: Paraglider namespace to operate in
        * ``cloud``: name of the cloud that the resource is in
        * ``resourceName``: Paraglider name of the resource

Add 
^^^

Adds one or many rules to the permit list associated with a resource.

.. tab-set::

    .. tab-item:: CLI
        :sync: cli

        .. code-block:: shell

            glide rule add <cloud> <resource_name> [--ssh <tag> --ping <tag> | --ruleFile <path_to_file>]

        Parameters:

        * ``cloud``: name of the cloud that the resource is in
        * ``resource_name``: Paraglider name of the resource
        * ``path_to_file``: path to JSON file describing rules to add
            * The file should describe rules in the following format:
            
            .. code-block:: JSON
                
                {
                    [
                    {
                        "name": "rulename",
                        "id": "id",
                        "tags": ["tagname"],
                        "direction": 0,
                        "src_port": 1,
                        "dst_port": 2,
                        "protocol": 3
                    }
                    ]
                }

        * ``tag``: Paraglider tag or IP/CIDR to allow SSH/ICMP traffic to/from

    .. tab-item:: REST
        :sync: rest

        .. tab-set::

            .. tab-item:: POST

                .. code-block:: shell
            
                    POST /namespaces/{namespace}/clouds/{cloud}/resources/{resourceName}/rules

                Creates/updates one rule of a resource's permit list.

                * Example Request Body:

                .. code-block:: JSON
                        
                    {
                        "name": "rulename",
                        "id": "id",
                        "tags": ["tagname"],
                        "direction": 0,
                        "src_port": 1,
                        "dst_port": 2,
                        "protocol": 3
                    }

                Parameters:

                * ``namespace``: Paraglider namespace to operate in
                * ``cloud``: name of the cloud that the resource is in
                * ``resourceName``: Paraglider name of the resource

            .. tab-item:: PUT

                .. code-block:: shell
                    
                    PUT /namespaces/{namespace}/clouds/{cloud}/resources/{resourceName}/rules/{ruleName}

                Creates/updates one rule of a resource's permit list.

                * Example Request Body:

                .. code-block:: JSON

                    {
                        "name": "rulename",
                        "id": "id",
                        "tags": ["tagname"],
                        "direction": 0,
                        "src_port": 1,
                        "dst_port": 2,
                        "protocol": 3
                    }

                Parameters:

                * ``namespace``: Paraglider namespace to operate in
                * ``cloud``: name of the cloud that the resource is in
                * ``resourceName``: Paraglider name of the resource
                * ``ruleName``: name of the rule 

                .. note::

                    If the name is provided in the request body, it will be ignored

            .. tab-item:: POST (bulk operation)

                .. code-block:: shell

                    POST /namespaces/{namespace}/clouds/{cloud}/resources/{resourceName}/applyRules

                Creates/updates rules of resource in bulk.

                * Example Request Body:

                .. code-block:: JSON

                    {
                        [
                        {
                            "name": "rulename",
                            "id": "id",
                            "tags": ["tagname"],
                            "direction": 0,
                            "src_port": 1,
                            "dst_port": 2,
                            "protocol": 3
                        }
                        ]
                    }

                Parameters:

                * ``namespace``: Paraglider namespace to operate in
                * ``cloud``: name of the cloud that the resource is in
                * ``resourceName``: Paraglider name of the resource

Delete
^^^^^^

Deletes one or many rules from the permit list associated with the specified resource.

.. tab-set::

    .. tab-item:: CLI
        :sync: cli

        .. code-block:: shell
            
            glide rule delete <cloud> <resource_name> --rules <rule_names>

        Parameters:

        * ``cloud``: name of the cloud that the resource is in
        * ``resource_name``: Paraglider name of the resource
        * ``rule_names``: list of rule names to delete

    .. tab-item:: REST
        :sync: rest

        .. tab-set::

            .. tab-item:: DELETE

                .. code-block:: shell

                    DELETE /namespaces/{namespace}/clouds/{cloud}/resources/{resourceName}/rules/{ruleName}

                Deletes one rule of a resource's permit list.

                Parameters:

                * ``namespace``: Paraglider namespace to operate in
                * ``cloud``: name of the cloud that the resource is in
                * ``resourceName``: Paraglider name of the resource
                * ``ruleName``: name of the rule 

            .. tab-item:: POST (bulk operation)

                .. code-block:: shell

                    POST /namespaces/{namespace}/clouds/{cloud}/resources/{resourceName}/deleteRules

                Deletes rules of resource in bulk.

                * Example Request Body:

                .. code-block:: JSON

                    {
                        [
                            "rulename1",
                            "rulename2"
                        ]
                    }

                Parameters:

                * ``namespace``: Paraglider namespace to operate in
                * ``cloud``: name of the cloud that the resource is in
                * ``resourceName``: Paraglider name of the resource


Tag Operations
--------------

Operations on Paraglider tags.

Get
^^^

Gets the children tags associated with a tag or resolves the tag down to last-level entries (IPs).

.. tab-set::

    .. tab-item:: CLI
        :sync: cli

        .. code-block:: shell

            glide tag get <tag> [--resolve]

        Parameters:

        * ``tag``: tag to get
        * ``resolve``: true/false value indicating whether to resolve to last-level tags or not

    .. tab-item:: REST
        :sync: rest

        .. code-block:: shell

            GET /tags/{tag}/

        .. code-block:: shell

            POST /tags/{tag}/resolve

        Parameters:

        * ``tag``: tag to get

Set
^^^

Adds children tags to a parent tag or creates a last-level tag that associates a names with an URI and/or IP.

.. tab-set::

    .. tab-item:: CLI
        :sync: cli

        .. code-block:: shell

            glide tag set <tag> [--children <child_tag_list>] | [--uri <uri>] [--ip <ip>]

        Parameters:

        * ``tag``: tag to set
        * ``children``: list of tags to add as children
        * ``uri``: uri to associate with tag
        * ``ip``: ip to associate with tag

    .. tab-item:: REST
        :sync: rest

        .. code-block:: shell

            POST /tags/{tag}/applyMembers

        * Example Request Body:

        .. code-block:: JSON
            
            {
                "tag_name": "tag",
                "uri": "uri",
                "ip": "1.1.1.1"
            }

        * Example Request Body
            
        .. code-block:: JSON
            
            {
                "tag_name": "tag",
                "child_tags": [
                    "child1",
                    "child2"
                ]
            }


        Parameters:
        * ``tag``: tag to set
        * ``children``: list of tags to add as children
        * ``uri``: uri to associate with tag
        * ``ip``: ip to associate with tag"

Delete
^^^^^^

Deletes a tag or the association of members tags to that tag.

.. tab-set::

    .. tab-item:: CLI
        :sync: cli

        .. code-block:: shell

            glide tag delete <tag> [--member <members_list>]

        Parameters:

        * ``tag``: tag to delete
        * ``member``: child tag to remove membership

    .. tab-item:: REST
        :sync: rest

        .. code-block:: shell

            DELETE /tags/{tag}/member/{member}

        Deletes a single member from a parent tag.

        Parameters:
        * ``tag``: parent tag
        * ``members``: child tag to remove membership

        .. code-block:: shell

            DELETE /tags/{tag}

        Deletes an entire tag (and all its child associations).

        Parameters:

        * ``tag``: tag to delete

Service Operations
------------------

Operations to interact with Paraglider services.

All Services
^^^^^^^^^^^^

.. tab-set::

    .. tab-item:: CLI
        :sync: cli

        .. code-block:: shell

            glided startup <path_to_config>
            

Orchestrator
^^^^^^^^^^^^
.. tab-set::

    .. tab-item:: CLI
        :sync: cli

        .. code-block:: shell

            glided orch <path_to_config>

Azure
^^^^^
.. tab-set::

    .. tab-item:: CLI
        :sync: cli

        .. code-block:: shell

            glided az <port> <central_controller_address>

        The ``central_controller_address`` should be the full host:port address where the central controller is hosted for RPC traffic. In the example config above, this is "localhost:8081".

GCP
^^^
.. tab-set::

    .. tab-item:: CLI
        :sync: cli

        .. code-block:: shell

            glided gcp <port> <central_controller_address>

        The ``central_controller_address`` should be the full host:port address where the central controller is hosted for RPC traffic. In the example config above, this is "localhost:8081".

Tag Service
^^^^^^^^^^^
.. tab-set::

    .. tab-item:: CLI
        :sync: cli

        .. code-block:: shell

            glided tagserv <redis_port> <server_port> <clear_keys>

        ``clear_keys`` is a bool ("true" or "false") which determines whether the database state should be cleared on startup or not.

Key-Value Store Service
^^^^^^^^^^^^^^^^^^^^^^^^
.. tab-set::

    .. tab-item:: CLI
        :sync: cli

        .. code-block:: shell

            glided kvserv <redis_port> <server_port> <clear_keys>

        ``clear_keys`` is a bool ("true" or "false") which determines whether the database state should be cleared on startup or not.
