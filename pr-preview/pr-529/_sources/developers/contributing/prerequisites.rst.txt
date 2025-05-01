.. _prerequisites:

Prerequisites
=============

Prerequisites for working with the repo
-----------------------------------------
This section lists the prerequisites for working with the repository. Most contributors should start with the basic prerequisites. 
Depending on the task you need to perform, you may need to install more tools.

We also provide a `Devcontainer <https://code.visualstudio.com/docs/devcontainers/containers>`_ for working with this repository without installing prerequisites. 
Keep reading for instructions.

Operating system
^^^^^^^^^^^^^^^^^^^^
We support developing on macOS, Linux and Windows with `WSL <https://docs.microsoft.com/windows/wsl/install>`_.

Asking for help
^^^^^^^^^^^^^^^^^^^^
If you get stuck installing any of our dependencies, you can raise an issue or ask for help in our `discord <https://discordapp.com/channels/1116864463832891502/11168644638328915074>`_.

Required tools
^^^^^^^^^^^^^^^^^^^^
This is the list of core dependencies to install for the most common tasks. In general we expect all contributors to have all of these tools present:

- `Git <https://git-scm.com>`_
- `Go <https://golang.org/>`_
- `golangci-lint <https://golangci-lint.run>`_
- `protoc <https://grpc.io/docs/protoc-installation>`_
- make

  * Linux: Install the ``build-essential`` package:

    .. code-block:: console
    
        $ apt install build-essential

    Then install ``make``:
  
    .. code-block:: console

        $ apt install make
  
  * Mac:

    Xcode

    .. code-block:: console  
        
        $ xcode-select --install
    
    Homebrew

    .. code-block:: console

        $ brew install make
    
Testing Required Tools
^^^^^^^^^^^^^^^^^^^^^^^
If you have not already done so, clone the repository and navigate there in your command shell.

You can build the main outputs using ``make``:

.. code-block:: console

    $ make build lint

Running these steps will run our build and lint steps and verify that the tools are installed correctly. 
If you get stuck or suspect something is not working in these instructions please raise an issue or ask for help in our Discord linked on our homepage.

**Integration/Multicloud Tests**

Our integration/multicloud tests perform real requests to cloud providers. You can run these with the following commands

.. code-block:: console

    $ make integration-test
    $ make multicloud-test

Note that the ``make test`` command only runs unit tests.

If you would like to run these locally, you will need to be authenticated. The following are the steps for each respective cloud provider.

**Google Cloud**

#. `Install the gcloud CLI <https://cloud.google.com/sdk/docs/install>`_. If you're using the dev container, this will already be installed for you.
#. `Set up your application default credentials <https://cloud.google.com/docs/authentication/provide-credentials-adc>`_.
#. Set the active project with ``gcloud config set project <project-id>``.
#. The tests will automatically create (and delete) new projects for each test run. You must set the environment variable ``PARAGLIDER_GCP_PROJECT_BILLING_ACCOUNT_NAME`` in the form of the ``billingAccount`` field of the `"ProjectBillingInfo" resource <https://cloud.google.com/billing/docs/reference/rest/v1/ProjectBillingInfo>`_.

   * If you'd like them to be created in a certain parent, set the environment variable ``PARAGLIDER_GCP_PROJECT_PARENT`` in the form of the `parent` field of the `"Project" resource <https://cloud.google.com/resource-manager/reference/rest/v3/projects#resource:-project>`_.
   
     .. warning::
        
        This requires privileges of creating projects and linking billing accounts.
    
   * If you want to use your own project, set the environment variable ``PARAGLIDER_GCP_PROJECT``. The order for deleting resources when deleting through the console: instances, VPN tunnels, VPN gateway + peer/external VPN gateways + router, VPC. The connectivity tests can be deleted at any time.
     
     .. warning::
        
        Resources will not automatically be cleaned up for you.

**Azure**

#. `Install azure cli <https://learn.microsoft.com/en-us/cli/azure/install-azure-cli>`_. If you're using the dev container, this will already be installed for you.
#. `Authenticate to your account with azure login <https://learn.microsoft.com/en-us/cli/azure/authenticate-azure-cli>`_.
#. The tests will automatically create (and delete) new resource groups for each test run. You must set the environment variable ``PARAGLIDER_AZURE_SUBSCRIPTION_ID`` with a valid subscription.
   
   * If you want to use your own existing resource group, set the environment variable ``PARAGLIDER_AZURE_RESOURCE_GROUP``. The tests will not delete the resource group and instead only clean up the resources within it.
    
     .. warning::
          
          Resource group must be created before running the test.


If you'd like to persist resources after a test (i.e., not teardown project/resource group), you can set the environment variable ``PARAGLIDER_TEST_PERSIST`` to ``1``.

**IBM** 

#. Set environment variable ``PARAGLIDER_IBM_API_KEY`` with an ``IAM API`` key. Create a key on `IBM's web console <https://cloud.ibm.com/iam/apikeys>`_. 
#. Set environment variable ``PARAGLIDER_IBM_RESOURCE_GROUP_ID`` with a resource group ID. 
   Pick a resource group from `IBM's web console <https://cloud.ibm.com/account/resource-groups>`__.

| Cleanup function, terminating all Paraglider resources on IBM, is executed automatically when tests end, unless ``INVISINETS_TEST_PERSIST`` is set to ``1``.

Editor
--------------------
If you don't have a code editor set up for Go, we recommend VS Code. The experience with VS Code is high-quality and approachable for newcomers.

Alternatively, you can choose whichever editor you are most comfortable for working on Go code. Feel free to skip this section if you want to make another choice.

- `Visual Studio Code <https://code.visualstudio.com/>`_
- `Go extension <https://marketplace.visualstudio.com/items?itemName=golang.go>`_

Launching VS Code
^^^^^^^^^^^^^^^^^^^^
The best way to launch VS Code for Go is to do *File* > *Open Folder* on the repository. 

You can easily do this from the command shell with ``code .``, which opens the current directory as a folder in VS Code.


Using the Dev Container
------------------------
Dev Containers allow you to run a development environment using VS Code inside a container. If you want to try this:

- Install `Docker <https://code.visualstudio.com/docs/devcontainers/containers#_system-requirements>`_
- Install `VS Code <https://code.visualstudio.com/>`_
- Install the `Dev Container extension <https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers>`_

Now when you open the Paraglider repo, you will be prompted with the option to open in a Dev Container. 
This will take a few minutes the first time to download and build the container, but will be much faster on subsequent opens.

Additional Tools
--------------------

Test summaries
^^^^^^^^^^^^^^^^^^^^
The default ``go test`` output can be hard to read when you have many tests. We recommend ``gotestsum`` as a tool to solve this. 
Our ``make test`` command will automatically use ``gotestsum`` if it is available.

- `gotestsum <https://github.com/gotestyourself/gotestsum#install>`_
