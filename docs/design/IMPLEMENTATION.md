# Controller Implementation
This doc covers the internal interfaces between each service in the controller. All of the components communicate via gRPC.

![gRPC interface diagram](grpc_interfaces.png)

Each service implements a gRPC service interface and may be a client to other servers in the overall controller. In the diagram, each box contains the gRPC service implemented by that service and has arrows to each service it is a client of. For example, the Central Controller implements the Controller Service, which each cloud plugin uses, and it is a client of each of the plugin services as well as the tag service.

Below, we provide references to the interfaces of each service.

## Central Controller

### Controller Interface
The `Controller` interface can be found in `invisinets.proto`. 

 TODO: Just document the proto file instead of statically repeating it here? But maybe we want to have explanations of why these interfaces are necessary -- not sure