# IBM Plugin

### Authentication

To use IBM services set the environment variable `PARAGLIDER_IBM_API_KEY` with your API key.
Create a new API key via the [web console](https://cloud.ibm.com/iam/apikeys), or by executing the following command:

```
ibmcloud iam api-key-create pgkey
```

### Instance Keys
Upon invoking `CreateResource`, local SSH keys will be created automatically in `~/.ibm/keys` and be registered on the IBM VPC platform in the specified region. The keys will be associated with the newly launched instance.  
New invocations of `CreateResource` will reuse the created keys and register the public key only if a key matching its value doesn't already exist in the region.

### Quotas
To maximize flexibility in the deployment's scale we recommend increasing the quota of the following resources by opening a ticket with cloud support:
- VPCs.
- Global Transit Gateway connections by disabling (setting to 0) all non VPC connections.  
  A user may further increase the number of connections by reducing the number of Global Transit Gateways per region.
  e.g., currently reducing the quota for TGW per region from 5 to 3 will raise max connections quota from 25 to 43.

### Testing
Tests require setting environment variable `PARAGLIDER_IBM_RESOURCE_GROUP_ID`.
The testing suit associates deployed resources with the specified resource ID.
Users may choose a resource group from [IBM's web console](https://cloud.ibm.com/account/resource-groups).

#### Resources Cleanup
To manually remove paraglider resources on IBM cloud users are offered a cleanup function located at `pkg/ibm_plugin/sdk/sdk_test.go`.
The function is automatically executed after integration tests, but can be manually run via `go test --tags=unit -run TestCleanup`.
Note: cleanup function removes all paraglider resources on IBM cloud.