## IBM Plugin

### Authentication
To use IBM services include your credentials in `~/.ibm/credentials.yaml`:

```yaml
iam_api_key: <KEY>
resource_group_id: <ID>
```

- Create a new API key by following this [guide](<https://www.ibm.com/docs/en/app-connect/container?topic=servers-creating-cloud-api-key>).
- Obtain a resource group ID (you're a member of) from the [web console](https://cloud.ibm.com/account/resource-groups).

### Instance Keys
Upon invoking `CreateResource`, local SSH keys will be created automatically in `~/.ibm/keys` and be registered on the IBM VPC platform in the specified region. The keys will be associated with the newly launched instance.  
New invocations of `CreateResource` will reuse said keys and register the public key only if a key matching its value doesn't already exist in the region.