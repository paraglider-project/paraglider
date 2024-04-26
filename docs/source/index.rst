Welcome to Paraglider!
======================================

.. image:: ./_static/paraglider-color-darkmode.png
    :width: 300
    :alt: Paraglider Logo
    :class: no-scaled-link, only-dark

.. image:: ./_static/paraglider-color-lightmode.png
   :width: 300
   :alt: Paraglider Logo
   :class: no-scaled-link, only-light


Paraglider is a cross-cloud control plane for configuring cloud networks. 

The Paraglider project aims to evolve cloud networking by simplifying the creation and management of single and multi-cloud networking. The project reduces the need for detailed networking knowledge from developers and administrators, and hides the complexity of low-level components like virtual networks, access control, load balancers, and inter-cloud connections. Paraglider provides high-level constructs for modeling connectivity and security as well as key network functions. Additionally, it provides mechanisms for semantically meaningful names and groups rather than limiting to IP-based constructs. The Paraglider configuration, in the form of connectivity requirements between networked resources (VMs, containers, PaaS resources, etc.), is then translated to cloud-specific configurations via plugins tailored for each platform.

Paraglider began as a research project at UC Berkeley in the NetSys Lab. The work was originally published in `HotOS <https://dl.acm.org/doi/pdf/10.1145/3458336.3465303>`_ and `NSDI <https://www.usenix.org/system/files/nsdi23-mcclure.pdf>`_. Since publication, the design goals for the implementation have shifted to support private address spaces, but still match the simplified interface proposed in the papers. 

The project is now run by an cross-industry working group consisting of members from Microsoft, Google, IBM, and UC Berkeley. It is now a Linux Foundation open-source project.

.. note::
   This project is under active development.

.. toctree::
   :maxdepth: 1
   :caption: Overview

   overview/quickstart.rst
   overview/concepts.rst
   overview/howitworks.rst
   overview/api.rst
   
.. toctree::
   :maxdepth: 1
   :caption: Developers

   developers/contributing.rst
   developers/plugin-interface.rst

.. toctree::
   :maxdepth: 1
   :caption: Examples

   examples/tags.rst
   examples/multicloud.rst
   
.. toctree::
   :maxdepth: 1
   :caption: Project Status

   project/feature-status.rst
   project/roadmap.rst
   project/known-issues.rst
