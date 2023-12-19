# Invisinets API
<img src="img/logo.png" alt="Invisinets Logo" width="200"/>

## Namespace Operations
Interact with the namespaces on the Invisinets Controller. The active namespace is a client-side CLI construct. All REST requests to the controller will be scoped on a namespace.

### Set

**CLI:**
`inv namespace set <namespace>`

Parameters:
* `namespace`: namespace to set on the controller

### Get 

**CLI:**
`inv namespace get`

### List

**CLI:**
`inv namespace list`

**HTTP:**
`GET /namespaces/`


## Resource Operations

### Create

Creates a resource according to the description provided in the speciied cloud. Some clouds may require a URI before resource creation and others may leave this field blank. Note that a tag is automatically created for the resource with the name `<namespace>.<cloud>.<vm_name>` (where `vm_name` is pulled from the name field in the resource description).

**CLI:**
`inv resource create <cloud> <resource_name> <path_to_json>`

Parameters:
* `cloud`: name of the cloud to create the resource in
* `resource_name` : name of the resource to be created in the Invisinets controller (note: this name will be scoped on cloud and namespace when stored)
* `path_to_json`: path to JSON file describing the resource to be created (excluding networking details)

**REST:** 
`POST /namespaces/{namespace}/clouds/{cloud}/resources/{resourceName}/create` 

* Example request body:

    ```
    {
    "id": "resource/uri",
    "description": "{
                    "location": "eastus",
                    "properties": {
                        "hardwareProfile": {
                            "vmSize": "Standard_B1s"
                        },
                        "osProfile": {
                            "adminPassword": "",
                            "adminUsername": "",
                            "computerName": "sample-compute"
                        },
                        "storageProfile": {
                            "imageReference": {
                                "offer": "debian-10",
                                "publisher": "Debian",
                                "sku": "10",
                                "version": "latest"
                            }
                        }
                    }
                }"
    }
    ```

Parameters:
* `namespace`: Invisinets namespace to operate in
* `cloud`: name of the cloud to create the resource in
* `resource_name` : name of the resource to be created in the Invisinets controller (note: this name will be scoped on cloud and namespace when stored)
* `id` : URI of the resource to create (required by Azure for metadata, can be left blank for GCP)
* `description`: JSON string describing the resource to be created (excluding networking details)


## Permit List Operations
These operations interact with the permit list associated with a given resource by adding/deleting/getting rules.

### Get

Gets the rules associated with a resource.

**CLI:**
`inv rule get <cloud> <resource_name>`

Parameters:
* `cloud`: name of the cloud that the resource is in
* `resource_name`: Invisinets name of the resource

**REST:**
`GET /namespaces/{namespace}/clouds/{cloud}/resources/{resourceName}/rules` 

Parameters:
* `namespace`: Invisinets namespace to operate in
* `cloud`: name of the cloud that the resource is in
* `resourceName`: Invisinets name of the resource

### Add 

Adds one or many rules to the permit list associated with a resource.

**CLI:** 
`inv rule add <cloud> <resource_name> [--ssh <tag> --ping <tag> | --ruleFile <path_to_file>]`

Parameters:
* `cloud`: name of the cloud that the resource is in
* `resource_name`: Invisinets name of the resource
* `path_to_file`: path to JSON file describing rules to add
* `tag`: Invisinets tag or IP to allow SSH/ICMP traffic to/from

**REST:**
`POST /namespaces/{namespace}/clouds/{cloud}/resources/{resourceName}/rules` 

Creates/updates one rule of a resource's permit list.

* Example Request Body:

    ```
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
    ```

Parameters:
* `namespace`: Invisinets namespace to operate in
* `cloud`: name of the cloud that the resource is in
* `resourceName`: Invisinets name of the resource


`PUT /namespaces/{namespace}/clouds/{cloud}/resources/{resourceName}/rules/{ruleName}`

Creates/updates one rule of a resource's permit list.

* Example Request Body:

    ```
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
    ```

Parameters:
* `namespace`: Invisinets namespace to operate in
* `cloud`: name of the cloud that the resource is in
* `resourceName`: Invisinets name of the resource
* `ruleName`: name of the rule 

***Note: If the name is provided in the request body, it will be ignored***

`POST /namespaces/{namespace}/clouds/{cloud}/resources/{resourceName}/applyRules`

Creates/updates rules of resource in bulk.

* Example Request Body:

    ```
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
    ```

Parameters:
* `namespace`: Invisinets namespace to operate in
* `cloud`: name of the cloud that the resource is in
* `resourceName`: Invisinets name of the resource

### Delete

Deletes one or many rules from the permit list associated with the specified resource.

**CLI:** 
`inv rule delete <cloud> <resource_name> --rules <rule_names>`

Parameters:
* `cloud`: name of the cloud that the resource is in
* `resource_name`: Invisinets name of the resource
* `rule_names`: list of rule names to delete

**REST:**
`DELETE /namespaces/{namespace}/clouds/{cloud}/resources/{resourceName}/rules/{ruleName}`

Deletes one rule of a resource's permit list.

Parameters:
* `namespace`: Invisinets namespace to operate in
* `cloud`: name of the cloud that the resource is in
* `resourceName`: Invisinets name of the resource
* `ruleName`: name of the rule 

`POST /namespaces/{namespace}/clouds/{cloud}/resources/{resourceName}/deleteRules`

Deletes rules of resource in bulk.

* Example Request Body:

    ```
    {
        [
            "rulename1",
            "rulename2"
        ]
    }
    ```

Parameters:
* `namespace`: Invisinets namespace to operate in
* `cloud`: name of the cloud that the resource is in
* `resourceName`: Invisinets name of the resource


## Tag Operations
Operations on Invisinets tags.

### Get

Gets the children tags associated with a tag or resolves the tag down to last-level entries (IPs).

**CLI:**
`inv tag get <tag> [--resolve]`

Parameters:
* `tag`: tag to get
* `resolve`: true/false value indicating whether to resolve to last-level tags or not

**REST:** 
`GET /tags/{tag}/` or `POST /tags/{tag}/resolve`

Parameters:
* `tag`: tag to get

### Set

Adds children tags to a parent tag or creates a last-level tag that associates a names with an URI and/or IP.

**CLI:** 
`inv tag set <tag> [--children <child_tag_list>] | [--uri <uri>] [--ip <ip>]`

Parameters:
* `tag`: tag to set
* `children`: list of tags to add as children
* `uri`: uri to associate with tag
* `ip`: ip to associate with tag

**REST:**
`POST /tags/{tag}/applyMembers`

* Example Request Body:

    ```
    {
    "tag_name": "tag",
    "uri": "uri",
    "ip": "1.1.1.1"
    }
    ```

* Example Request Body
    ```
    {
    "tag_name": "tag",
    "child_tags": [
        "child1",
        "child2"
    ]
    }
    ```

Parameters:
* `tag`: tag to set
* `children`: list of tags to add as children
* `uri`: uri to associate with tag
* `ip`: ip to associate with tag

### Delete

Deletes a tag or the association of members tags to that tag.

**CLI:**
`inv tag delete <tag> [--member <members_list>]`

Parameters:
* `tag`: tag to delete
* `member`: child tag to remove membership

**REST:**
`DELETE /tags/{tag}/member/{member}`

Deletes a single member from a parent tag.

Parameters:
* `tag`: parent tag
* `members`: child tag to remove membership

`DELETE /tags/{tag}`

Deletes an entire tag (and all its child associations).

Parameters:
* `tag`: tag to delete
