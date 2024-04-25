.. _api:

API
===

Namespace Operations
--------------------
Interact with the namespaces on the Paraglider Controller. The active namespace is a client-side CLI construct. All REST requests to the controller will be scoped on a namespace.

Set
^^^

**CLI:**

.. code-block:: shell

    glide namespace set <namespace>

Parameters:

* ``namespace``: namespace to set on the controller

Get
^^^

Gets the current active namespace in the CLI (Note: this is only a CLI feature).

**CLI:**

.. code-block:: shell

    glide namespace get

List
^^^^

Lists all namespaces configured on the controller.

**CLI:**

.. code-block:: shell

    glide namespace list

**HTTP:**

.. code-block:: shell

    GET /namespaces/

Resource Operations
-------------------

Create
^^^^^^

Creates a resource according to the description provided in the specified cloud. Some clouds may require a URI before resource creation and others may leave this field blank. Note that a tag is automatically created for the resource with the name ``<namespace>.<cloud>.<vm_name>`` (where ``vm_name`` is pulled from the name field in the resource description).

**CLI:**

.. code-block:: shell
    
    glide resource create <cloud> <resource_name> <path_to_json>

Parameters:

* ``cloud``: name of the cloud to create the resource in
* ``resource_name`` : name of the resource to be created in the Invisinets controller (note: this name will be scoped on cloud and namespace when stored)
* ``path_to_json``: path to JSON file describing the resource to be created (excluding networking details)

**REST:**

.. code-block:: shell

    POST /namespaces/{namespace}/clouds/{cloud}/resources/{resourceName}

* Example request body:

    .. code-block:: JSON

        {
            "id": "resource/uri",
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
                                    \"offer\": \"debian-10\",
                                    \"publisher\": \"Debian\",
                                    \"sku\": \"10\",
                                    \"version\": \"latest\"
                                }
                            }
                        }
                    }"
        }

Parameters:

* ``namespace``: Invisinets namespace to operate in
* ``cloud``: name of the cloud to create the resource in
* ``name`` : name of the resource to be created in the Invisinets controller (note: this name will be scoped on cloud and namespace when stored)
* ``id`` : URI of the resource to create (required by Azure for metadata, can be left blank for GCP)
* ``description``: JSON string describing the resource to be created (excluding networking details)

.. code-block:: shell
    
    PUT /namespaces/{namespace}/clouds/{cloud}/resources/{resourceName}

* Example request body:

    .. code-block:: JSON
        
        {
        "id": "resource/uri",
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
                                    \"offer\": \"debian-10\",
                                    \"publisher\": \"Debian\",
                                    \"sku\": \"10\",
                                    \"version\": \"latest\"
                                }
                            }
                        }
                    }"
        }

Parameters:

* ``namespace``: Invisinets namespace to operate in
* ``cloud``: name of the cloud to create the resource in
* ``resource_name`` : name of the resource to be created in the Invisinets controller (note: this name will be scoped on cloud and namespace when stored)
* ``id`` : URI of the resource to create (required by Azure for metadata, can be left blank for GCP)
* ``description``: JSON string describing the resource to be created (excluding networking details)

Permit List Operations
----------------------

These operations interact with the permit list associated with a given resource by adding/deleting/getting rules.

Get
^^^

Gets the rules associated with a resource.

**CLI:**

.. code-block:: shell
    
    glide rule get <cloud> <resource_name>

Parameters:

* ``cloud``: name of the cloud that the resource is in
* ``resource_name``: Invisinets name of the resource

**REST:**

.. code-block:: shell

    GET /namespaces/{namespace}/clouds/{cloud}/resources/{resourceName}/rules

Parameters:

* ``namespace``: Invisinets namespace to operate in
* ``cloud``: name of the cloud that the resource is in
* ``resourceName``: Invisinets name of the resource

Add 
^^^

Adds one or many rules to the permit list associated with a resource.

**CLI:** 

.. code-block:: shell

    glide rule add <cloud> <resource_name> [--ssh <tag> --ping <tag> | --ruleFile <path_to_file>]

Parameters:

* ``cloud``: name of the cloud that the resource is in
* ``resource_name``: Invisinets name of the resource
* ``path_to_file``: path to JSON file describing rules to add
* ``tag``: Invisinets tag or IP to allow SSH/ICMP traffic to/from

**REST:**

.. code-block:: shell
    
    POST /namespaces/{namespace}/clouds/{cloud}/resources/{resourceName}/rules

Creates/updates one rule of a resource's permit list.

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

* ``namespace``: Invisinets namespace to operate in
* ``cloud``: name of the cloud that the resource is in
* ``resourceName``: Invisinets name of the resource

.. code-block:: shell
    
    PUT /namespaces/{namespace}/clouds/{cloud}/resources/{resourceName}/rules/{ruleName}

Creates/updates one rule of a resource's permit list.

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

* ``namespace``: Invisinets namespace to operate in
* ``cloud``: name of the cloud that the resource is in
* ``resourceName``: Invisinets name of the resource
* ``ruleName``: name of the rule 


.. note::

    If the name is provided in the request body, it will be ignored

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

* ``namespace``: Invisinets namespace to operate in
* ``cloud``: name of the cloud that the resource is in
* ``resourceName``: Invisinets name of the resource

Delete
^^^^^^

Deletes one or many rules from the permit list associated with the specified resource.

**CLI:**

.. code-block:: shell
    
    glide rule delete <cloud> <resource_name> --rules <rule_names>

Parameters:

* ``cloud``: name of the cloud that the resource is in
* ``resource_name``: Invisinets name of the resource
* ``rule_names``: list of rule names to delete

**REST:**

.. code-block:: shell

    DELETE /namespaces/{namespace}/clouds/{cloud}/resources/{resourceName}/rules/{ruleName}

Deletes one rule of a resource's permit list.

Parameters:

* ``namespace``: Invisinets namespace to operate in
* ``cloud``: name of the cloud that the resource is in
* ``resourceName``: Invisinets name of the resource
* ``ruleName``: name of the rule 

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

* ``namespace``: Invisinets namespace to operate in
* ``cloud``: name of the cloud that the resource is in
* ``resourceName``: Invisinets name of the resource


Tag Operations
--------------

Operations on Invisinets tags.

Get
^^^

Gets the children tags associated with a tag or resolves the tag down to last-level entries (IPs).

**CLI:**

.. code-block:: shell
    
    glide tag get <tag> [--resolve]

Parameters:

* ``tag``: tag to get
* ``resolve``: true/false value indicating whether to resolve to last-level tags or not

**REST:**

.. code-block:: shell
    
    GET /tags/{tag}/
    POST /tags/{tag}/resolve

Parameters:

* ``tag``: tag to get

Set
^^^

Adds children tags to a parent tag or creates a last-level tag that associates a names with an URI and/or IP.

**CLI:**

.. code-block:: shell

    glide tag set <tag> [--children <child_tag_list>] | [--uri <uri>] [--ip <ip>]

Parameters:

* ``tag``: tag to set
* ``children``: list of tags to add as children
* ``uri``: uri to associate with tag
* ``ip``: ip to associate with tag

**REST:**

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
* ``ip``: ip to associate with tag

Delete
^^^^^^

Deletes a tag or the association of members tags to that tag.

**CLI:**

.. code-block:: shell
    
    glide tag delete <tag> [--member <members_list>]

Parameters:

* ``tag``: tag to delete
* ``member``: child tag to remove membership

**REST:**

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

.. code-block:: shell

    glided startup <path_to_config>
            

Orchestrator
^^^^^^^^^^^^

.. code-block:: shell

    glided orch <path_to_config>

Azure
^^^^^

.. code-block:: shell

    glided az <port> <central_controller_address>

The ``central_controller_address`` should be the full host:port address where the central controller is hosted for RPC traffic. In the example config above, this is "localhost:8081".

GCP
^^^


.. code-block:: shell

    glided gcp <port> <central_controller_address>

The ``central_controller_address`` should be the full host:port address where the central controller is hosted for RPC traffic. In the example config above, this is "localhost:8081".

Tag Service
^^^^^^^^^^^

.. code-block:: shell

    glided tagserv <redis_port> <server_port> <clear_keys>

``clear_keys`` is a bool ("true" or "false") which determines whether the database state should be cleared on startup or not.
