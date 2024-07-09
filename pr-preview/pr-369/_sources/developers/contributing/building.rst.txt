.. _building:

Building The Project
=======================

Building the code
------------------------

Paraglider uses a Makefile to build the repository and automate most common repository tasks.

You can build the repository with ``make build``. This will build all of the packages and executables. 
The first time you run ``make build`` it may take a few minutes because it will download and build dependencies. Subsequent builds will be faster because they can use cached output.

The following command will build, run unit tests, and run linters. This command is handy for verifying that your local changes are working correctly.

.. code-block:: console

    $ make build lint test

Binaries
^^^^^^^^^^^^^^^

There are two main binaries that are built by the repository: ``glide`` and ``glided``. These are the CLIs for the Paraglider client and server, respectively.
See the :ref:`api` for more information on how to use these binaries.

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
