Welcome to Paraglider!
======================================

.. raw:: html

   <br />
   <a class="github-button" href="https://github.com/paraglider-project/paraglider" data-size="large" data-show-count="true" aria-label="Star paraglider-project/paraglider on GitHub">Star</a>
   <!-- Place this tag in your head or just before your close body tag. -->
   <script async defer src="https://buttons.github.io/buttons.js"></script>

.. image:: https://img.shields.io/discord/1116864463832891502?logo=discord&logoColor=white&logoSize=auto&label=Discord&labelColor=7289DA&color=17cf48&link=https%3A%2F%2Fdiscord.gg%2FKrZGbfZ7wm
   :alt: Discord
   :target: https://discord.gg/KrZGbfZ7wm
   :height: 28

The Paraglider project aims to simplify the creation and management of single-cloud and multi-cloud networks. It reduces the need for developers and administrators to have detailed networking knowledge, hiding the complexity of components like virtual networks, access controls, load balancers, and inter-cloud connections.

Paraglider provides high-level constructs for modeling connectivity, security, and key network functions. It also offers mechanisms for using semantically meaningful names and groups instead of IP-based constructs. The Paraglider configuration, expressed as connectivity requirements between networked resources (VMs, containers, PaaS resources, etc.), is translated into cloud-specific configurations through plugins tailored for each cloud platform.

Ultimately, Paraglider delivers a unified cross-cloud control plane that streamlines cloud networking.

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

