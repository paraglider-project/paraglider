.. _multicloudexample:

Multicloud Example
==================

Goals
------
* Create two VMs in Azure in different regions and connect them together
* Create a third VM in GCP and connect to one of the Azure VMs

.. mermaid ::

   graph LR

      subgraph Azure
      A("A<br>(westus)") <---> B("B<br>(eastus)")
      end

      subgraph GCP
      C[C]
      end

      A <---> C

Setup
------

Installation
^^^^^^^^^^^^^^

.. code-block:: console

    $ git clone https://github.com/paraglider-project/paraglider
    $ cd paraglider
    $ make build install

Controller Setup
^^^^^^^^^^^^^^^^^^

.. code-block:: console

    $ glided startup <path_to_config>

You can find example configuration files in the ``tools/examples/controller-configs`` directory.

.. note::

    Be sure to replace the template values for the GCP project and the Azure resource group in the template.

For this example, we assume that you have set up the necessary credentials for Azure and GCP and that you have configured your Paraglider controller with a ``default`` namespace for both clouds. For more on how to do this, see the :ref:`quickstart` or :ref:`controllersetup`.

Resource Configurations
^^^^^^^^^^^^^^^^^^^^^^^^

This example uses the following templated configuration files in the repo. You can find them in the ``tools/examples/``.
    * ``vm-configs/azure-vm-westus.json``
    * ``vm-configs/azure-vm-eastus.json``
    * ``vm-configs/gcp-vm.json``

Phase 0: Multicloud Prep
------------------------

Steps
^^^^^^

1. Create VM A in Azure

   .. code-block:: console

        $ glide resource create azure vm-a <path/to/azure-vm-westus.json>

2. Create VM C in GCP

   .. code-block:: console

        $ glide resource create gcp vm-c <path/to/gcp-vm.json>

3. Log into VM C and try to ping VM A. Add the following rule to allow the in-browser SSH tool from GCP. The ping should fail.

   .. code-block:: console

        $ glide rule add gcp vm-c --ssh 35.235.240.0/20

4. Set the permit list on VM C to allow pings from VM A.

   .. code-block:: console

        $ glide rule add gcp vm-c --ping default.azure.vm-a

   .. note::
    
        This will set up the multicloud infrastructure (a VPN tunnel between the two clouds). Provisioning the gateways necessary for this can take ~20 minutes, but it is a one-time cost. All multicloud connections in this deployment will be able to use this gateway afterwards.


Phase 1: Multi-Region connectivity
----------------------------------

Steps
^^^^^^

1. Create VM B in Azure

   .. code-block:: console

        $ glide resource create azure vm-b <path/to/azure-vm-eastus.json>

2. Set the permit list on VM ato allow pings to VM B.
    
   .. code-block:: console
    
        $ glide rule add azure vm-a --ping default.azure.vm-b

3. Log into VM A and try to ping VM B. The ping should fail.

   * You can log into the VM using the serial console in-browser tool from Azure to avoid having to change the permit list.

4. Set the permit list on VM B to allow pings from VM A.

   .. code-block:: console

        $ glide rule add azure vm-b --ping default.azure.vm-a

5. Log into VM A and try to ping VM B. The ping should succeed.

Phase 2: Multicloud connectivity
--------------------------------

Steps
^^^^^^

1. Picking up where we left off with the multicloud connection, log into VM C and try to ping VM A. The ping should fail.

2. Set the permit list on VM A to allow pings from VM C.

   .. code-block:: console

        $ glide rule add azure vm-a --ping default.gcp.vm-c

3. Try to ping VM A from VM C. The ping should succeed.

4. Get the permit list of VM A.
    
   .. code-block:: console
    
        $ glide rule get azure vm-a

4. Remove a permit list rule allowing pings from VM A's permit list.

   .. code-block:: console

        $ glide rule delete azure vm-a --rules ping-in-default-gcp-vm-c

5. Try to ping VM A from VM C. The ping should fail.
