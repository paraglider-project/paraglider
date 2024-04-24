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
            
           Take note of the ``id`` field for the subscription ID and resource group name (referred to as ``${AZURE_SUBSCRIPTION_ID}`` and ``${AZURE_RESOURCE_GROUP_NAME}`` throughout this document).

    .. tab-item:: GCP
        :sync: gcp

        #. `Install the Google Cloud CLI <https://cloud.google.com/sdk/docs/install>`_.
        #. Set up your application default credentials.
        
           .. code-block:: console

                $ gcloud auth application-default login
                $ gcloud auth login

           .. note::

                For using Invisinets, you only need to setup application default credentials (i.e., first command). However, throughout this example, we will be using some ``gcloud`` commands that require authentication.

        #. Retrieve the project ID you would like to use.

           .. code-block:: console

                $ gcloud projects list

           Take note of the ``GCP_PROJECT_ID`` column for the project ID (referred to as ``${GCP_PROJECT_ID}`` throughout this document).

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
                port: 8082

            tagService:
              host: "localhost"
              port: 8083

            namespaces:
              default:
                - name: "azure"
                  deployment: "/subscriptions/${AZURE_SUBSCRIPTION_ID}/resourceGroups/${AZURE_RESOURCE_GROUP_NAME}"


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
                port: 8082

            tagService:
              host: "localhost"
              port: 8083

            namespaces:
              default:
                - name: "gcp"
                  deployment: "projects/${GCP_PROJECT_ID}"

Here is a breakdown of the configuration file:

#. ``server`` defines the orchestrator's host and ports. The orchestrator has two ports: ``port`` for an HTTP server for users and ``rpcPort`` for an RPC server for cloud plugins.
#. ``cloudPlugins`` lists the cloud plugins that Invisinets will use. In this example, we only specify one cloud but you can specify multiple clouds.
#. ``tagService`` defines the host and port for the tag service.
#. ``namespaces`` lists the namespaces that Invisinets will reference. Each namespace consists of a list of clouds that specifies the cloud name and deployment URI.

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

        #. Copy the following into a file called ``azure_vm.json``. Make sure to fill in the ``adminUsername`` and ``adminPassword`` fields!

           .. code-block:: json

                {
                    "location": "eastus",
                    "properties": {
                        "hardwareProfile": {
                            "vmSize": "Standard_B1s"
                        },
                        "osProfile": {
                            "computerName": "sample-compute",
                            "adminUsername": "<your-username>",
                            "adminPassword": "<your-password>"
                        },
                        "storageProfile": {
                            "imageReference": {
                                "offer": "0001-com-ubuntu-minimal-jammy",
                                "publisher": "canonical",
                                "sku": "minimal-22_04-lts-gen2",
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

Ping VMs
--------

Now that your VMs are created, you can try pinging between the two VMs. Since Invisinets denies all traffic by default, the ping should fail.

Since Invisinets creates VMs without public IPs, you will need to use cloud specific connectivity checks instead of SSH-ing into the VMs which may require some setup.

.. tab-set::

    .. tab-item:: Azure
        :sync: azure

        #. Configure Azure Network Watcher.
        
           .. code-block:: console

                $ az network watcher configure -g ${AZURE_RESOURCE_GROUP_NAME} -l eastus --enabled true
        
        #. Install the Network Watcher Agent extension on both VMs.

           .. code-block:: console

                $ az vm extension set -g ${AZURE_RESOURCE_GROUP_NAME} --vm-name vm-1 --name NetworkWatcherAgentLinux --publisher Microsoft.Azure.NetworkWatcher --version 1.4
                $ az vm extension set -g ${AZURE_RESOURCE_GROUP_NAME} --vm-name vm-2 --name NetworkWatcherAgentLinux --publisher Microsoft.Azure.NetworkWatcher --version 1.4
        
        #. Check connectivity between vm-1 and vm-2.

           .. code-block:: console
    
                $ az network watcher test-connectivity -g ${AZURE_RESOURCE_GROUP_NAME} --source-resource vm-1 --dest-resource vm-2 --protocol Icmp

           You should see the ``connectionStatus`` be ``Unreachable``. If you look at the ``issues`` fields closely, you'll notice that the issue is due to network security rules called invisinets-deny-all-outbound (for source) and invisinets-deny-all-inbound (for destination).

    .. tab-item:: GCP
        :sync: gcp

        #. Run connectivity test between vm-1 and vm-2.

           .. code-block:: console

                $ gcloud network-management connectivity-tests create vm-1-to-vm-2 \
                    --source-instance=projects/${GCP_PROJECT_ID}/zones/us-west1-a/instances/vm-1 \
                    --destination-instance=projects/${GCP_PROJECT_ID}/zones/us-west1-a/instances/vm-2 \
                    --project=${GCP_PROJECT_ID} \
                    --protocol=ICMP
                $ gcloud network-management connectivity-tests describe vm-1-to-vm-2 --project=${GCP_PROJECT_ID}

           You should see the ``result`` field be ``UNREACHABLE``. If you look at the ``steps`` fields closely, you'll notice that the invisinets-default-deny-all-egress rule is blocking the traffic.

Add Permit List Rules
---------------------

To get the VMs to talk to each other, you will need to add permit list rules to both VMs.

.. tab-set::

    .. tab-item:: Azure
        :sync: azure

        #. Add permit list rules to both VMs.

           .. code-block:: console

                $ inv rule add azure vm-1 --ping default.azure.vm-2
                $ inv rule add azure vm-2 --ping default.azure.vm-1
    
        #. Check connectivity again between vm-1 and vm-2.

           .. code-block:: console
    
                $ az network watcher test-connectivity -g ${AZURE_RESOURCE_GROUP_NAME} --source-resource vm-1 --dest-resource vm-2 --protocol Icmp
            
           You should see the ``connectionStatus`` be ``Reachable``.

    .. tab-item:: GCP
        :sync: gcp

        #. Add permit list rules to both VMs.

           .. code-block:: console

                $ inv rule add gcp vm-1 --ping default.gcp.vm-2
                $ inv rule add gcp vm-2 --ping default.gcp.vm-1

        #. Check connectivity again between vm-1 and vm-2.

           .. code-block:: console

                $ gcloud network-management connectivity-tests rerun vm-1-to-vm-2 --project=${GCP_PROJECT_ID}

           You should see the ``result`` field be ``REACHABLE``.
