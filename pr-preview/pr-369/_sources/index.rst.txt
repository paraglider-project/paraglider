Welcome to Paraglider!
======================================

.. raw:: html

   <br />
   <a href="https://discord.gg/KrZGbfZ7wm"><img src="https://dcbadge.vercel.app/api/server/KrZGbfZ7wm?compact=true&?compact=true" /></a>
   <a class="github-button" href="https://github.com/paraglider-project/paraglider" data-size="large" data-show-count="true" aria-label="Star paraglider-project/paraglider on GitHub">Star</a>

   <!-- Place this tag in your head or just before your close body tag. -->
   <script async defer src="https://buttons.github.io/buttons.js"></script>

Paraglider is a cross-cloud control plane for configuring cloud networks. 

The Paraglider project aims to evolve cloud networking by simplifying the creation and management of single and multi-cloud networking. 
The project reduces the need for detailed networking knowledge from developers and administrators, and hides the complexity of low-level components like virtual networks, access control, load balancers, and inter-cloud connections. Paraglider provides high-level constructs for modeling connectivity and security as well as key network functions. Additionally, it provides mechanisms for semantically meaningful names and groups rather than limiting to IP-based constructs. 
The Paraglider configuration, in the form of connectivity requirements between networked resources (VMs, containers, PaaS resources, etc.), is then translated to cloud-specific configurations via plugins tailored for each platform.

Paraglider began as a research project at UC Berkeley in the NetSys Lab. The work was originally published in `HotOS <https://dl.acm.org/doi/pdf/10.1145/3458336.3465303>`_ and `NSDI <https://www.usenix.org/system/files/nsdi23-mcclure.pdf>`_. 
Since publication, the design goals for the implementation have evolved to support private address spaces, but still match the simplified interface proposed in the papers. 

The project is now run by an cross-industry working group consisting of members from Microsoft, Google, IBM, and UC Berkeley. It is a Linux Foundation open-source project.

Check out the `GitHub repository <https://github.com/paraglider-project/paraglider>`_ for the latest code and issues.

.. note::
   This project is under active development.

.. toctree::
   :maxdepth: 1
   :caption: Overview

   overview/what-is-paraglider.rst
   overview/concepts.rst
   overview/howitworks.rst
   overview/api.rst
   overview/quickstart.rst

.. toctree::
   :maxdepth: 1
   :caption: Examples

   examples/controller-setup.rst
   examples/tags.rst
   examples/multicloud.rst
   
.. toctree::
   :maxdepth: 1
   :caption: Project Status

   project/feature-status.rst
   project/roadmap.rst
   
.. toctree::
   :maxdepth: 1
   :caption: Developers

   developers/contributing.rst
   developers/plugin-interface.rst

