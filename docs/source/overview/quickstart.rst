.. _quickstart:

Quickstart
==========

This guide will walk you through an example of how to use Invisinets to ping two VMs within a single cloud.

Installation
------------

.. code-block:: console

    $ git clone https://github.com/invisinets/invisinets.git
    $ cd invisinets
    $ make build install

Cloud Authentication
--------------------

Invisinets currently supports Azure and GCP. To use Invisinets with a cloud provider, you must have an account with that provider and have the necessary credentials set up.

.. tab-set::

    .. tab-item:: Azure
        :sync: azure

        #. `Install the Azure CLI <https://learn.microsoft.com/en-us/cli/azure/install-azure-cli>`_.
        #. Authenticate to your Azure account.

           .. code-block:: console

                $ az login

    
        #. Retrieve the subscription ID and resource group name you would like to use.

           .. code-block:: console

                $ az group list

            
           Take note of the ``id`` field for the subscription ID and resource group name.

    .. tab-item:: GCP
        :sync: gcp

        #. `Install the Google Cloud CLI <https://cloud.google.com/sdk/docs/install>`_.
        #. Set up your application default credentials.
        
           .. code-block:: console

                $ gcloud auth application-default login

        #. Retrieve the project ID you would like to use.

           .. code-block:: console

                $ gcloud projects list

           Take note of the ``PROJECT_ID`` column for the project ID.

Configuration
-------------

Copy paste the following configuration into a new file called ``invisinets_config.yaml``. Make sure to substitute the necessary parameters for your cloud provider.

.. tab-set::
    
    .. tab-item:: Azure
        :sync: azure

        .. code-block:: yaml

            server: 
            host: "localhost"
            port: 8080
            rpcPort: 8081

            cloudPlugins:
            - name: "azure"
              host: "localhost"
              port: 1000
              invDeployment: "/subscriptions/<subscription_id>/resourceGroups/<resource_group_name>"

    .. tab-item:: GCP
        :sync: gcp

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


The ``cloudPlugins`` list may contain one or multiple cloud plugins. Though all listed should be reachable (otherwise, requests to the central controller may only result in errors). The ``server`` section is used to describe where the central controller will bind on the local machine to serve the HTTP server for users (``port``) and the RPC server for the cloud plugins (``rpcPort``). All other hosts/ports are where the other services are expected to be and may or may not be locally hosted. 

The ``invDeployment`` parameter in the cloud plugin specification includes the minimum URI necessary to find the Invisinets resources for that cloud. In GCP, this is project ID while in Azure this is the resource group URI.

Startup Services
----------------

This command will start up all services specified in the configuration. In this case, that would be the orchestrator and the cloud plugin.

.. code-block:: console

    $ invd startup invisinets_config.yaml

Create VMs
----------

To create VMs in clouds, Invisinets requires a JSON file that describes the VM. This is the same as what you would provide in the body of the REST API request to the cloud.

.. tab-set::

    .. tab-item:: Azure
        :sync: azure

        #. Copy the following into a file called ``azure_vm.json``.

           .. code-block:: json

                {
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
                }


        #. Create two VMs called ``vm-1`` and ``vm-2``.

           .. code-block:: console
            
                $ inv resource create azure vm-1 azure_vm.json
                $ inv resource create azure vm-2 azure_vm.json

    .. tab-item:: GCP
        :sync: gcp

        #. Copy the following into a file called ``gcp_vm.json``.

           .. code-block:: json

                { 
                    "instance_resource": { 
                        "disks": [{
                            "auto_delete": true,
                            "boot": true,
                            "initialize_params": {
                                "disk_size_gb": 10,
                                    "source_image": "projects/debian-cloud/global/images/family/debian-10"
                                },
                            "type": "PERSISTENT"
                        }],
                        "machine_type": "zones/us-west1-a/machineTypes/f1-micro",
                    },
                    "zone": "us-west1-a"
                }

        #. Create two VMs called ``vm-1`` and ``vm-2``.

           .. code-block:: console

                $ inv resource create gcp vm-1 gcp_vm.json
                $ inv resource create gcp vm-2 gcp_vm.json
