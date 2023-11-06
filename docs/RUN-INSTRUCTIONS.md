# How to run the Invisinets Controller
The controller consists of a central orchestrating controller that sends requests to per-cloud plugins/controllers and a tag service. 

## Configuration
The central controller takes a configuration file in the following format.

```server: 
  host: "localhost"
  port: 8080
  rpcPort: 8081

cloudPlugins:
   - name: "gcp"
     host: "localhost"
     port: 1000
     invDeployment: "projects/<project_name>"
   - name: "azure"
     host: "localhost"
     port: 1001
     invDeployment: "/subscriptions/<sub_id>/resourceGroups/<resource_group_name>"

tagService:
  host: "localhost"
  port: 6000
```

The `cloudPlugins` list may contain one or multiple cloud plugins. Though all listed should be reachable (otherwise, requests to the central controller may only result in errors). The `server` section is used to describe where the central controller will bind on the local machine to serve the HTTP server for users (`port`) and the RPC server for the cloud plugins (`rpcPort`). All other hosts/ports are where the other services are expected to be and may or may not be locally hosted. 

The `invDeployment` parameter in the cloud plugin specification includes the minimum URI necessary to find the Invisinets resources for that cloud. In GCP, this is project ID while in Azure this is the resource group URI.

If no tags are used, the `tagService` does not have to be running for requests to complete.

## Central Controller
To run the central controller from the `/cmd/inv` directory, run:

`go run main.go frontend <path_to_config>`

## Cloud Plugins

### Azure
To run the azure plugin from the `/cmd/inv` directory, run:
`go run main.go az <port> <central_controller_address>`

The `central_controller_address` should be the full host:port address where the central controller is hosted for RPC traffic. In the example config above, this is "localhost:8081".

### GCP 
To run the azure plugin from the `/cmd/inv` directory, run:

`go run main.go gcp <port> <central_controller_address>`

The `central_controller_address` should be the full host:port address where the central controller is hosted for RPC traffic. In the example config above, this is "localhost:8081".

## Tag Service
To run the azure plugin from the `/cmd/inv` directory, run:

`go run main.go tagserv <redis_port> <server_port> <clear_keys>`

`clear_keys` is a bool ("true" or "false") which determines whether the database state should be cleared on startup or not.

## Cloud Resources
In order for the cloud plugins to correctly use their SDKs, ensure that these steps have been completed.

### Azure

1. [Install azure cli](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli). If you're using the dev container, this will already be installed for you.
2. [Authenticate to your account with azure login](https://learn.microsoft.com/en-us/cli/azure/authenticate-azure-cli).

### Google Cloud

1. [Install the gcloud CLI](https://cloud.google.com/sdk/docs/install). If you're using the dev container, this will already be installed for you.
2. [Set up your application default credentials](https://cloud.google.com/docs/authentication/provide-credentials-adc).
