.. _multicloudexample:

Multicloud Example
==================

Goals:
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

Setup:
------
* Run ``invd startup <path_to_config>`` to start all the microservices

Phase 0: Multicloud Prep
------------------------

Steps:

1. Create VM A in Azure

   .. code-block:: console

        inv resource create azure vm-a <path/to/azure-vm-westus.json>

2. Create VM C in GCP

   .. code-block:: console

        inv resource create gcp vm-c <path/to/gcp-vm.json>

3. Log into VM C and try to ping VM A. Add the following rule to allow the in-browser SSH tool from GCP. The ping should fail.

    .. code-block:: console
    
        inv rule add gcp vm-c --ssh 35.235.240.0/20

4. Set the permit list on VM C to allow pings from VM A. This will set up the multicloud infrastructure (this takes some time).

    .. code-block:: console

        inv rule add gcp vm-c --ping default.azure.vm-a


Phase 1: Multi-Region connectivity
----------------------------------

Steps:

1. Create VM B in Azure

   .. code-block:: console

        inv resource create azure vm-b <path/to/azure-vm-eastus.json>

2. Set the permit list on VM ato allow pings to VM B.
    
     .. code-block:: console
    
        inv rule add azure vm-a --ping default.azure.vm-b

3. Log into VM A and try to ping VM B. The ping should fail.

4. Set the permit list on VM B to allow pings from VM A.

    .. code-block:: console

        inv rule add azure vm-b --ping default.azure.vm-a

5. Log into VM A and try to ping VM B. The ping should succeed.

Phase 2: Multicloud connectivity
--------------------------------

Steps:

1. Log into VM C and try to ping VM A. The ping should fail.

2. Set the permit list on VM A to allow pings from VM C.

    .. code-block:: console

        inv rule add azure vm-a --ping default.gcp.vm-c

3. Try to ping VM A from VM C. The ping should succeed.

4. Remove the permit list rules allowing pings from VM C's permit list.

    .. code-block:: console

        inv rule delete azure vm-a --ping default.gcp.vm-c

5. Try to ping VM A from VM C. The ping should fail.
