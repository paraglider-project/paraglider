Welcome to Paraglider!
======================================

.. image:: ./_static/paraglider-logo-dark-transparent.png
    :width: 200
    :alt: Paraglider Logo
    :class: only-dark

.. image:: ./_static/paraglider-logo-light-transparent.png
   :width: 200
   :alt: Paraglider Logo
   :class: only-light

Paraglider is a cross-cloud control plane for configuring cloud networks. 

The Paraglider project aims to evolve cloud networking by simplifying the creation and management of single and multi-cloud networking. The project reduces the need for detailed networking knowledge from developers and administrators, and hides the complexity of low-level components like virtual networks, access control, load balancers, and inter-cloud connections. Invisinets provides high-level constructs for modeling connectivity and security as well as key network functions. Additionally, it provides mechanisms for semantically meaningful names and groups rather than limiting to IP-based constructs. The Invisinets configuration, in the form of connectivity requirements between networked resources (VMs, containers, PaaS resources, etc.), is then translated to cloud-specific configurations via plugins tailored for each platform.

Paraglider began as a research project at UC Berkeley in the NetSys Lab. It is now run by an cross-industry working group consisting of members from Microsoft, Google, IBM, and UC Berkeley. It is now a Linux Foundation open-source project.

.. note::
   This project is under active development.

.. toctree::
   :maxdepth: 1
   :caption: Overview

   overview/quickstart.rst
   overview/design.rst
   overview/api.rst
   
.. toctree::
   :maxdepth: 1
   :caption: Developers

   developers/contributing.rst
