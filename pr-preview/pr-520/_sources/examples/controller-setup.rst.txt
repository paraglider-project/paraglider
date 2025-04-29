.. _controllersetup:

Controller Setup
==================
This page explains how to set up the Paraglider controller. The controller consists of many microservices which communicate via RPCs. 
Each microservice can be run on a different machine, but in this guide we will assume that all microservices are running on the same machine.
For information on the commands for running each individual microservice, see :ref:`api`.

Configuration
---------------
The controller is configured using a configuration file. The configuration file is a YAML file with the following fields:

.. code-block:: yaml

    server: 
        host: "localhost"
        port: 8080
        rpcPort: 8081

    cloudPlugins:
        - name: "gcp"
          host: "localhost"
          port: 8082
        - name: "azure"
          host: "localhost"
          port: 8083
        - name: "ibm"
          host: "localhost"
          port: 8084

    namespaces: 
        default:
            - name: "azure"
              deployment: "/subscriptions/${AZURE_SUBSCRIPTION_ID}/resourceGroups/${AZURE_RESOURCE_GROUP}"
            - name: "gcp"
              deployment: "projects/${GCP_PROJECT_ID}"
            - name: "ibm"
              deployment: "/resourcegroup/${IBM_RESOURCE_GROUP}"

    tagService:
        host: "localhost"
        port: 8085

    kvStore:
        host: "localhost"
        port: 8086

This file contains all information needed to spin up each of the microservices.

* The ``server`` field determines where the main controller service should be hosted (for user REST requests and plugin RPCs). This service is the frontend to the controller and orchestrates the other services.
* The ``cloudPlugins`` field determines where the each cloud plugin should be hosted.
* The ``namespaces`` field contains information about the namespaces. Each namespace has a name and consists of at least one cloud deployment.

  * A cloud deployment consists of the name of the cloud ("azure", "gcp", or "ibm") and the ID of the deployment. Exactly what maps to a deployment depends on the cloud. In Azure and IBM, this is a resource group. In GCP, it is a project.

* The ``tagService`` field determines where the tag service should be hosted.
* The ``kvStore`` field determines where the key-value store should be hosted.

.. note: 
    The key-value store service can be omitted if none of the plugins require it. Currently, only the IBM plugin requires it.

.. _feature_flags:

Feature Flags
~~~~~~~~~~~~~
The controller supports feature flags for each of the cloud plugins. 
The feature flags are set in the configuration file under the ``featureFlags`` field. 
Each plugin can have its own set of feature flags.
To see which features are currently supported by each plugin, see :ref:`feature-status`.
There are currently three feature flags:

* ``attachResourceEnabled``: Enables attaching existing resources (not created with Paraglider) to the deployment (i.e., using the :ref:`attach operation <attach_resource>`).
* ``kubernetesClustersEnabled``: Enables creating Kubernetes clusters in the deployment (i.e., providing a cluster description to the :ref:`create resource operation <create_resource>`).
* ``privateEndpointsEnabled``: Enables creating private endpoints (eg, Private Endpoints in Azure, Private Service Connect in GCP) in the deployment (ie, providing a cluster description to the :ref:`create resource operation <create_resource>`).

Below is an example of how to set the feature flags in the configuration file:

.. code-block:: yaml

    featureFlags:
        azure:
            attachResourceEnabled: true
            kubernetesClustersEnabled: true
            privateEndpointsEnabled: false
        gcp:
            attachResourceEnabled: false
            kubernetesClustersEnabled: false
            privateEndpointsEnabled: true
        ibm:
            attachResourceEnabled: false
            kubernetesClustersEnabled: true
            privateEndpointsEnabled: false

.. note:
    All feature flags are set to ``false`` by default. If a feature flag is not set, it will be treated as false.


Running the Controller
-----------------------
To run the controller all locally, you need to run the following command:

.. code-block:: console

    $ glided startup <path_to_config_file>

Alternatively, all microservices can be spun up individually. For information on the commands for running each individual microservice, see :ref:`api`.
