# Invisinets

Invisinets is a cross-cloud control plane for configuring networking. 

## Current status

Invisinets is in the prototype phase, and we're currently building it with a small cross-industry team.

## Contributing

See the [contributing guide](./CONTRIBUTING.md) for ways to contribute and instructions.

## Code of Conduct

This project has adopted the code of conduct defined by the Contributor Covenant to clarify expected behavior in our community.
For more information, see the [Contributor Covenant Code of Conduct 2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

## Known Issues

### `gopls` Linting Issue in Testing Files on Package Declartion Line
You may see the following error from `gopls` in the `*_test.go` files.

```
This file is within module ".", which is not included in your workspace.
To fix this problem, you can add a go.work file that uses this directory.
See the documentation for more information on setting up your workspace:
https://github.com/golang/tools/blob/master/gopls/doc/workspace.md.
```

This is due to a known issue within `gopls` (https://github.com/golang/go/issues/29202). You can work around this in VS Code by specifying the following in your `settings.json`.

```
"go.buildTags": "unit,integration"
```
