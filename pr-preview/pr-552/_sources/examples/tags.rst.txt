.. _tagexample:

Tag Example
===========

Goals
------
* Create a tag for an IP address
* Add a parent tag for the IP tag
* Reference the parent tag in a resource's permit list
* Add a new tag to the parent tag
* See that the resource's permit list has been updated accordingly

Installation
------------

.. code-block:: console

    $ git clone https://github.com/paraglider-project/paraglider
    $ cd paraglider
    $ make build install

Controller Setup
----------------

.. code-block:: console

    $ glided startup <path_to_config>

You can find example configuration files in the ``tools/examples/controller-configs`` directory.

.. note::

    This example will create a VM in GCP. You can create the VM in whichever cloud you prefer. Make sure that your chosen cloud provider is configured in the controller configuration file.

Steps
------

1. Create a tag for an IP address with name `iptag`

   .. code-block:: console

        $ glide tag set iptag --ip 1.1.1.1

2. Assign `iptag` to a parent tag named `parenttag`

   .. code-block:: console

        $ glide tag set parenttag --children iptag


3. Resolve the parent tag down to list of names

   .. code-block:: console
    
        $ glide tag get parenttag --resolve

4. Create a resource name `vm1`

   .. code-block:: console
    
        $ glide resource create gcp vm1 <path_to_config>

   .. note::

      You can find example configuration files in the ``tools/examples/vm-configs`` directory.

4. Add a rule referencing the parent tag to a resource

   .. code-block:: console
    
        $ glide rule add gcp vm1 --ping parenttag

5. Create a tag, `iptag2`

   .. code-block:: console
    
        $ glide tag set iptag2 --ip 2.2.2.2

6. Add `iptag2` to `parenttag`

   .. code-block:: console
    
         $ glide tag set parenttag --children iptag2

7. Get the permit list of the resource we added to

   .. code-block:: console
    
        $ glide rule get gcp vm1

8. Resolve the parent tag

   .. code-block:: console
    
        $ glide tag get parenttag --resolve
