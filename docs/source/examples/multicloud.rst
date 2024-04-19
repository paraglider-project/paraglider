.. _multicloudexample:

Multicloud Example
==================

Goals:
------
* Create two VMs in Azure in different regions and connect them together
* Create a third VM in GCP and connect to one of the Azure VMs

.. image:: ../_static/multicloud-diagram.png
    :width: 400px

Setup:
------
* Run ``invd startup <path_to_config>`` to start all the microservices

Phase 0: Multicloud Prep
------------------------

Steps:

1. Create VM A in Azure

   .. code-block:: console
   
        inv resource create azure vm-a azure-vm-westus.json

2. Create VM C in GCP