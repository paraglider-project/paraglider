# Azure Plugin

## Introduction
This README provides guidance on adding new functions to the plugin and outlines the testing practices, including unit and integration testing.

## Table of Contents
- [Getting Started](#getting-started)
  - [Local Development and Testing](#local-development-and-testing)
- [Package Structure](#package-structure)
- [Adding a New Paraglider API Function to the Plugin](#adding-a-new-paraglider-api-function-to-the-plugin)
- [Testing](#testing)
  - [Unit Tests](#unit-tests)
    - [`plugin.go`](#plugingo)
    - [`sdk_handler.go`](#sdk_handlergo)
  - [Integration Testing](#integration-testing)
    - [Setup and Environment Variables](#setup-and-environment-variables)
    - [Integration Test Function](#integration-test-function)
    - [Adjusting Timeout for Local Testing](#adjusting-timeout-for-local-testing)


## Getting Started
- Configure the project following instructions in [CONTRIBUTING.md](https://github.com/paraglider-project/paraglider/blob/main/CONTRIBUTING.md).
### Local Development and Testing

If you're not working within the dev container, here are the steps to set up your local environment for testing and validation:

1. **Install Azure CLI**: Ensure you have the Azure CLI installed by following the instructions in [this guide](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli). After installation, run `az login` to authenticate with your Azure account.

2. **Valid Azure Subscription**: If you're testing the `azure` functions locally to ensure your code's functionality, make sure you have access to a valid Azure subscription. This subscription is necessary for authenticating your local testing with Azure services.
It's important to note that most requests might require a valid resource ID, which typically includes a subscription ID and a resource group name. As the current assumption is that the resource group already exists, ensure that you have a valid subscription ID and that the necessary resource group has been created prior to running your testing code.

For local testing purposes, consider adding a `main` function within the `plugin.go` file. This can be used to execute your server logic independently and validate its behavior. Here's an example of how you can do this:

1. Add a `main` function in `plugin.go`:
   ```go
   func main() {
       c := context.Background()
       s := azurePluginServer{
           azureHandler: &azureSDKHandler{},
       }

       // Call the function you want to test
       resp, err := s.AddPermitListRules(c, &paragliderpb.PermitList{
           // Define the input parameters here
       })

       if err != nil {
           // Handle errors
       }

       // Use resp as needed
   }

2. Run the server:
   ```bash
   go run .\pkg\azure\plugin_server.go .\pkg\azure\azure_sdk_handler.go
## Package Structure
The `azure` contains essential components and functionalities related to Azure integration. Within the `azure` package, you will find the following key files:

- `plugin.go`: Serving as the primary entry point for the project, this file implements the core Paraglider API functions. It acts as the interface between the external API requests and the underlying logic within the `azure` package.
- `sdk_handler.go`: This file encapsulates the communication with Azure Resource Manager (ARM) for managing Azure resources. It consolidates the actual server requests made to Azure, providing a streamlined approach for resource management. 
- `integration_test.go`: This file contains integration tests specifically focused on Azure functionality. It validates the plugin funcitonality and the server integration with azure services.
- `plugin_test.go`: Dedicated to unit tests, this file ensures the reliability and correctness of the server implementation within the `azure` package. 
- `sdk_handler_test.go`: Focused solely on unit tests, this file tests the `sdk_handler` functionalities. It verifies that the  the responses are handled appropriately by redirecting ARM requests to a fake server.

## Adding a New Paraglider API fucntion to the Plugin

Follow these steps to ensure consistent structure and seamless integration.

1. Open `plugin.go`:
   - Add a new function following the same structure as specified in Paraglider APIs. For example:
     ```go
     func (s *azurePluginServer) GetPermitList(ctx context.Context, input *paragliderpb.GetPermitListRequest) (*paragliderpb.GetPermitListResponse, error) {
         // Implementation here
     }
     ```

2. Initialize the Handler:
   - In your new API function, you might need to initialize the sdk handler. If the API requires specific information like subscription ID or resource group name, extract these details from the request and set up the handler. Example:
     ```go
     resourceIdInfo, err := getResourceIDInfo(input.ResourceID)
     if err != nil {
         logger.Log.Printf("An error occurred while getting resource ID info: %+v", err)
         return nil, err
     }
     err = s.setupAzureHandler(resourceIdInfo)
     if err != nil {
         return nil, err
     }
     ```

3. Handling ARM Requests:
   - If your new API needs to make ARM requests, check if the required functionality is already implemented in `sdk_handler.go`. If not, add a new function in the handler that wraps the Azure request. Call this new function from the `plugin` file. Any helper functionalities relevant only to Paraglider and the server can remain in `plugin`.

4. Interface and Mock Implementation:
   - If you add a function in the handler, add its definition to the `AzureSDKHandler` interface in `sdk_handler.go`.

5. Update Testing:
   - In `plugin_test.go`, provide a mocked implementation of your new handler function for testing purposes. For instance:
     ```go
     func (m *mockAzureSDKHandler) NewHandlerFunction(ctx context.Context, args ...) (*armType, error) {
         // Mock implementation here
     }
     ```
   - Ensure that your mock function implements the corresponding `AzureSDKHandler` method signature.


## Testing

When adding new functionality to the `azure` package, it's crucial to ensure that the code is thoroughly tested to maintain reliability and stability. The testing process is divided into unit tests and integration tests.

### Unit Tests

#### `plugin.go`:
As the `plugin.go` file depends on the `sdk_handler.go` file, unit tests here will involve mocking the server requests made by the handler.

1. Mock Azure Handler:
   - For each function in `plugin.go` that involves server requests, mock the relevant handler function calls using your mocking framework.
   - If additional input and output validation is needed, customize the mock function behavior accordingly.
   - After setting up the mock, use `mockAzureHandler.AssertExpectations(t)` to ensure the expected calls were made with the correct parameters.

#### `sdk_handler.go`:
This file contains a fake server implementation that routes Azure requests to it.

1. Fake Server Setup:
   - If your new function involves making Azure requests, ensure that the fake server in `sdk_handler_test.go` is aware of these requests.
   - In the `initializeReqRespMap` function, add an entry for the new request URL mapping to its corresponding response.
   - If the URL is already present but for a different request method, check if you need to include it in the `urlToResponse` map.

2. Test Function Setup:
   - In your unit test function, include `Once.Do(setup)` to initialize the fake server and the response map.

Note: This unit test structure primarily validates request handling and code structure. It doesn't verify actual functionality since server requests are mocked.

### Integration Testing

Integration tests play a critical role in ensuring that the extended functionalities of the `azure` package interact seamlessly and consistently with the Azure environment. These tests create an isolated environment for each run by provisioning a dedicated resource group. The teardown process involves removing the resource group, thus effectively eliminating any resources that were created during testing.

#### Setup and Environment Variables

1. **Isolated Resource Group**: Each integration test run creates a dedicated resource group to maintain an isolated environment. The resource group's name is prefixed by the GitHub run number when running in a GitHub Action workflow. For local testing, the run number is empty.
2. **INVISINETS_AZURE_SUBSCRIPTION_ID**: When running tests locally, ensure that the environment variable `INVISINETS_AZURE_SUBSCRIPTION_ID` is set with your Azure subscription ID. For GitHub Actions, this subscription ID should be set as a secret in the repository.

#### Integration Test Function

The primary integration test function, `TestAzurePluginIntegration`, should orchestrate various scenarios to validate the extended features of the `azure` package. This function serves as a container for subtests, each targeting specific scenarios or functionalities. While this structure enables a single resource group for all subtests, you may need to refactor it when different scenarios demand separate resource groups to prevent interference between tests.

#### Adjusting Timeout for Local Testing

When running integration tests locally, you should adjust the test timeout to ensure completion within the expected time frame. If using tools like VSCode, the default timeout might be set to 30 seconds. In this context, consider increasing the timeout to accommodate the longer execution time of integration tests. A timeout of around 10 minutes (`10m`) can be a reasonable starting point.

By conducting thorough integration tests with dedicated resource groups, controlled environments, and comprehensive scenarios, you can confidently validate the robustness and effectiveness of your extended `azure` package functionalities.

