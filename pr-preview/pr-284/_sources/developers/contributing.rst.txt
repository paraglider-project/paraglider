.. _contributing:

Contributing
========================================

Welcome to the Paraglider! We're currently building Paraglider with a small cross-industry team. 

This page gives an overview of how to contribute to the project. Please read over this document for some important basics. For specific topics, refer to the table of contents.

.. toctree::
   :maxdepth: 1
   :caption: Contents:

   contributing/prerequisites.rst
   contributing/building.rst
   contributing/contributing-issues.rst
   contributing/writing-go.rst
   contributing/known-issues.rst

Overview
----------
Paraglider provides a streamlined interface for users to manage their cloud network resources.
Cloud customers interact with the Paraglider APIs exposed by the Paraglider controller. 
The controller is responsible for provisioning and updating the relevant cloud network resources based on the requests from the user. 
The controller includes plugins for each cloud it supports which are responsible for translating the Paraglider configuration to the cloud-specific configuration.
For more information about the design and architecture, please refer to :ref:`howitworks`.

Guidelines
------------------
We always welcome minor contributions like documentation improvements, typo corrections, bug fixes, and minor features in the form of pull requests. 
You are also welcome to `choose an existing issue <https://github.com/paraglider-project/paraglider/issues>`_, or `create an issue to work on <https://github.com/paraglider-project/paraglider/issues/new>`_.

* But please work with the maintainers to ensure that what you're doing is in scope for the project before writing any code.
* If you have any doubt whether a contribution would be valuable, feel free to ask.

Developer Certificate of Origin
---------------------------------
The Paraglider project follows the `Developer Certificate of Origin <https://developercertificate.org/>`_. This is a lightweight way for contributors to certify that they wrote or otherwise have the right to submit the code they are contributing to the project.

Contributors sign-off that they adhere to these requirements by adding a Signed-off-by line to commit messages.

.. code-block:: text

    This is my commit message

    Signed-off-by: Random J Developer <random@developer.example.org>

We provide a Git Hook to automatically add this line to your commit messages. You can install it by running the following command after installing the repo.

.. code-block:: console

    $ git config --local core.hooksPath .githooks/

If you'd like to do this manually, git has a ``-s`` command line option to append this automatically to your commit message:

.. code-block:: console

    $ git commit -s -m 'This is my commit message'

Visual Studio Code has a setting, git.alwaysSignOff to automatically add a Signed-off-by line to commit messages. Search for "sign-off" in VS Code settings to find it and enable it.


Creating issues
--------------------
Please create issues for needed work and bugs in the `repo <https://github.com/paraglider-project/paraglider/issues>`_.


Sending pull requests
----------------------
Please send pull requests for all changes, even if they are urgent.

Code of Conduct
--------------------

This project has adopted the code of conduct defined by the Contributor Covenant to clarify expected behavior in our community.
For more information, see the `Contributor Covenant Code of Conduct 2.1 <https://www.contributor-covenant.org/version/2/1/code_of_conduct/>`_.


Troubleshooting and getting help
---------------------------------
* Have a question? - Visit our Discord (linked on our homepage) to post your question and we'll get back to you ASAP
* Found an issue? - Refer to :ref:`contributingissues` on filing a bug report
* Have a proposal? - Refer to :ref:`contributingissues` for instructions on filing a feature request

