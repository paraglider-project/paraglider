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