.. _building:

Building The Project
=======================

Building the code
------------------------
Paraglider uses a Makefile to build the repository and automate most common repository tasks.

You can run ``make`` (no additional arguments) to see the list of targets and their descriptions.

You can build the repository with ``make build``. This will build all of the packages and executables. 
The first time you run ``make build`` it may take a few minutes because it will download and build dependencies. Subsequent builds will be faster because they can use cached output.

The following command will build, run unit tests, and run linters. This command is handy for verifying that your local changes are working correctly.

.. code-block:: console

    $ make build lint test

Built binaries
^^^^^^^^^^^^^^^
There are two main binaries that are built by the repository: ``glide`` and ``glided``. These are the CLIs for the Paraglider client and server, respectively.
See the :ref:`api` for more information on how to use these binaries.

Installing the code
^^^^^^^^^^^^^^^^^^^^^
After building the code, you can run ``make install`` to install the binaries to your ``/usr/local/bin`` directory. This will allow you to run the binaries from anywhere on your system.

Documentation
-------------

All of our documentation is located in ``docs/``. We use `Sphinx <https://www.sphinx-doc.org/>`_ to generate our documents. 

Setup
^^^^^^^^^

.. code-block:: console
    
    $ python -m venv .venv
    $ source .venv/bin/activate
    $ pip install -r docs/requirements.txt

Building
^^^^^^^^^^^

.. code-block:: console

    $ cd docs
    $ make html

Viewing
^^^^^^^^^^^

.. code-block:: console

    $ python -m http.server

Navigate to ``localhost:8000``.

Troubleshooting and getting help
---------------------------------
You might encounter error messages while running various ``make`` commands due to missing dependencies. Review the prerequisites listed above for installation instructions.

If you get stuck working with the repository, please ask for help by `raising an issue on Github <https://github.com/paraglider-project/paraglider/issues/new>`_ or in our Discord (linked on our home page). 
We're always interested in ways to improve the tooling, so please feel free to report problems and suggest improvements.

If you need to report an issue with the Makefile, we may ask you for a dump of the variables. You can see the state of all of the variables our Makefile defines with ``make dump``. The output will be quite large so you might want to redirect this to a file.

