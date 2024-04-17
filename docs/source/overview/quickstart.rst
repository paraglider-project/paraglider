.. _quickstart:

Quickstart
==========

The controller consists of a orchestrator that sends requests to per-cloud plugins/controllers and a tag service. These services can be started individually or all at once on the localhost.

Build / Install
---------------
Run the following command to build and install the CLI locally.

.. code-block:: shell

    make build install

CLI
---
All of the services can be started using the ``invd`` CLI. For additional help, look at the help docs in the CLI.

Configuration
-------------
The orchestrator takes a configuration file in the following format.

.. code-block:: yaml

    server: 
    host: "localhost"
    port: 8080
    rpcPort: 8081

    cloudPlugins:
    - name: "gcp"
        host: "localhost"
        port: 1000
        invDeployment: "projects/<project_name>"
    - name: "azure"
        host: "localhost"
        port: 1001
        invDeployment: "/subscriptions/<sub_id>/resourceGroups/<resource_group_name>"

    tagService:
    host: "localhost"
    port: 6000


The ``cloudPlugins``` list may contain one or multiple cloud plugins. Though all listed should be reachable (otherwise, requests to the central orchestrator may only result in errors). The ``server`` section is used to describe where the orchestrator will bind on the local machine to serve the HTTP server for users (``port``) and the RPC server for the cloud plugins (``rpcPort``). All other hosts/ports are where the other services are expected to be and may or may not be locally hosted. 

The ``invDeployment`` parameter in the cloud plugin specification includes the minimum URI necessary to find the Invisinets resources for that cloud. In GCP, this is project ID while in Azure this is the resource group URI.

If no tags are used, the ``tagService`` does not have to be running for requests to complete.

Startup All Services
--------------------

Using the CLI, run:
^^^^^^^^^^^^^^^^^^^

.. code-block:: shell

    invd startup <path_to_config>

Orchestrator
^^^^^^^^^^^^

Using the CLI, run:

.. code-block:: shell

    invd orch <path_to_config>

Cloud Plugins
-------------

Azure
^^^^^

Using the CLI, run:

.. code-block:: shell

    invd az <port> <orchestrator_address>

The ``orchestrator_address`` should be the full host:port address where the orchestrator is hosted for RPC traffic. In the example config above, this is "localhost:8081".

GCP
^^^

Using the CLI, run:

.. code-block:: shell

    invd gcp <port> <orchestrator_address>

The ``orchestrator_address`` should be the full host:port address where the orchestrator is hosted for RPC traffic. In the example config above, this is "localhost:8081".

Tag Service
-----------

Using the CLI, run:

.. code-block:: shell

    invd tagserv <redis_port> <server_port> <clear_keys>

``clear_keys`` is a bool ("true" or "false") which determines whether the database state should be cleared on startup or not.

Cloud Resources
---------------

In order for the cloud plugins to correctly use their SDKs, ensure that these steps have been completed.

Azure
^^^^^

1. `Install azure cli <https://learn.microsoft.com/en-us/cli/azure/install-azure-cli>`_. If you're using the dev container, this will already be installed for you.
2. `Authenticate to your account with azure login <https://learn.microsoft.com/en-us/cli/azure/authenticate-azure-cli>`_.

Google Cloud
^^^^^^^^^^^^

1. `Install the gcloud CLI <https://cloud.google.com/sdk/docs/install>`_. If you're using the dev container, this will already be installed for you.
2. `Set up your application default credentials <https://cloud.google.com/docs/authentication/provide-credentials-adc>`_.
