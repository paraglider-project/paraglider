# IBM Plugin

### Authentication
To use IBM services include your credentials in `~/.ibm/credentials.yaml`:

```yaml
iam_api_key: <KEY>
```

- Create a new API key by following this [guide](<https://www.ibm.com/docs/en/app-connect/container?topic=servers-creating-cloud-api-key>).

### Instance Keys
Upon invoking `CreateResource`, local SSH keys will be created automatically in `~/.ibm/keys` and be registered on the IBM VPC platform in the specified region. The keys will be associated with the newly launched instance.  
New invocations of `CreateResource` will reuse the created keys and register the public key only if a key matching its value doesn't already exist in the region.

### Quotas
To maximize flexibility in the deployment's scale we recommend increasing the quota of the following resources by opening a ticket with cloud support:
- VPCs.
- Global Transit Gateway connections by disabling (setting to 0) all non VPC connections.  
  A user may further increase the number of connections by reducing the number of Global Transit Gateways per region.
  e.g., currently reducing the quota for TGW per region from 5 to 3 will raise max connections quota from 25 to 43.