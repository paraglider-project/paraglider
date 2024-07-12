.. _prerequisites:

Prerequisites
=============

This section lists the prerequisites for working with the repository.
Most contributors should start with the basic prerequisites. 
Depending on the task you need to perform, you may need to install more tools.

VS Code Setup
-------------

We recommend using VS Code for Paraglider development because we provide a `dev container <https://code.visualstudio.com/docs/devcontainers/containers>`_ that will automatically install all of the prerequisites for you.

#. `Get VS Code set up to use dev containers <https://code.visualstudio.com/docs/devcontainers/containers#_getting-started>`_.
#. `In VS Code, open the cloned repository in a container <https://code.visualstudio.com/docs/devcontainers/containers#_quick-start-open-an-existing-folder-in-a-container>`_.

   .. note::
  
        The first time you open the repository in a container, it will take a while to download and install the prerequisites.
        Subsequent opens will be much faster.

#. `Install the Go extension <https://marketplace.visualstudio.com/items?itemName=golang.go>`_.
#. Configure linter.
   
   You may see the following error from ``gopls`` in the ``*_test.go`` files.

      This file is within module ".", which is not included in your workspace.
      To fix this problem, you can add a go.work file that uses this directory.
      See the documentation for more information on setting up your workspace:
      https://github.com/golang/tools/blob/master/gopls/doc/workspace.md.

   Specify the following in your ``settings.json``.

   .. code-block:: json

      "go.buildTags": "unit,integration,multicloud"

Required Tools
--------------

This is the list of core dependencies to install for the most common tasks.
In general we expect all contributors to have all of these tools present.

- `make <https://www.gnu.org/software/make/>`_
- `Go <https://golang.org/>`_
- `protoc <https://grpc.io/docs/protoc-installation>`_
- `protoc-gen-go <https://pkg.go.dev/google.golang.org/protobuf/cmd/protoc-gen-go>`_
- `protoc-gen-go-grpc <https://pkg.go.dev/google.golang.org/grpc/cmd/protoc-gen-go-grpc>`_
- `redis <https://redis.io>`_
- `golangci-lint <https://golangci-lint.run>`_

Running Functional Tests
------------------------

Paraglider uses both unit and functional tests.
While unit tests use a fake cloud provider, functional tests make API calls to real cloud providers, which requires further setup.

You can run these with the following commands

.. code-block:: console

    $ make integration-test
    $ make multicloud-test

Note that the ``make test`` command only runs unit tests.

If you would like to run these locally, you will need to be authenticated.
The following are the steps for each respective cloud provider.

Google Cloud
^^^^^^^^^^^^

#. `Install the gcloud CLI <https://cloud.google.com/sdk/docs/install>`_. If you're using the dev container, this will already be installed for you.
#. `Set up your application default credentials <https://cloud.google.com/docs/authentication/provide-credentials-adc>`_.
#. Set the active project with ``gcloud config set project <project-id>``.
#. The tests will automatically create (and delete) new projects for each test run. You must set the environment variable ``PARAGLIDER_GCP_PROJECT_BILLING_ACCOUNT_NAME`` in the form of the ``billingAccount`` field of the `"ProjectBillingInfo" resource <https://cloud.google.com/billing/docs/reference/rest/v1/ProjectBillingInfo>`_.

   * If you'd like them to be created in a certain parent, set the environment variable ``PARAGLIDER_GCP_PROJECT_PARENT`` in the form of the `parent` field of the `"Project" resource <https://cloud.google.com/resource-manager/reference/rest/v3/projects#resource:-project>`_.
   
     .. warning::
        
        This requires privileges of creating projects and linking billing accounts.
    
   * If you want to use your own project instead of creating a new one, set the environment variable ``PARAGLIDER_GCP_PROJECT``. The order for deleting resources when deleting through the console: instances, VPN tunnels, VPN gateway + peer/external VPN gateways + router, VPC. The connectivity tests can be deleted at any time.
     
     .. warning::
        
        The project will not be deleted, and resources allocated by the tests will not automatically be cleaned up for you.

Azure
^^^^^

#. `Install azure cli <https://learn.microsoft.com/en-us/cli/azure/install-azure-cli>`_. If you're using the dev container, this will already be installed for you.
#. `Authenticate to your account with azure login <https://learn.microsoft.com/en-us/cli/azure/authenticate-azure-cli>`_.
#. The tests will automatically create (and delete) new resource groups for each test run. You must set the environment variable ``PARAGLIDER_AZURE_SUBSCRIPTION_ID`` with a valid subscription.
   
   * If you want to use your own existing resource group, set the environment variable ``PARAGLIDER_AZURE_RESOURCE_GROUP``. The tests will not delete the resource group and instead only clean up the resources within it.
    
     .. warning::
          
          Resource group must be created before running the test.

IBM
^^^

#. Set environment variable ``PARAGLIDER_IBM_API_KEY`` with an ``IAM API`` key. Create a key on `IBM's web console <https://cloud.ibm.com/iam/apikeys>`_. 
#. Set environment variable ``PARAGLIDER_IBM_RESOURCE_GROUP_ID`` with a resource group ID. 
   Pick a resource group from `IBM's web console <https://cloud.ibm.com/account/resource-groups>`__.

Persisting Resources
^^^^^^^^^^^^^^^^^^^^

The functional tests will automatically clean up any resources they create before completing the test run.
If you'd like to persist resources after a test (i.e., not teardown project/resource group), you can set the environment variable ``PARAGLIDER_TEST_PERSIST`` to ``1``.

Optional Tools
--------------

- `gotestsum <https://github.com/gotestyourself/gotestsum#install>`_ for better test summaries
  
  The default ``go test`` output can be hard to read when you have many tests.
  We recommend ``gotestsum`` as a tool to solve this. 
  Our ``make test`` command will automatically use ``gotestsum`` if available.
