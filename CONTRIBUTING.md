# Contributing to Invisinets

Welcome to the repo! We're currently building Invisinets with a small cross-industry team. We'll update this guidance further as we move closer to being a public open source project.

## Creating issues

Please create issues for needed work and bugs in this repo.

## Sending pull requests

Please send pull requests for all changes, even if they are urgent.

## Prerequisites for working with the repo

This section lists the prerequisites for working with the repository. Most contributors should start with the basic prerequisites. Depending on the task you need to perform, you may need to install more tools.

### Operating system

We support developing on macOS, Linux and Windows with [WSL](https://docs.microsoft.com/windows/wsl/install).

### Asking for help

If you get stuck installing any of our dependencies, please ask for help in our [discord](https://discordapp.com/channels/1116864463832891502/11168644638328915074).

### Required tools

This is the list of core dependencies to install for the most common tasks. In general we expect all contributors to have all of these tools present:

- [Git](https://git-scm.com/downloads)
- [Go](https://golang.org/doc/install)
- [Golangci-lint](https://golangci-lint.run/usage/install/#local-installation)
  
- Make  
  
  **Linux**: Install the `build-essential` package:
  ```bash
  sudo apt-get install build-essential
  ```
  **Mac**:
  Using Xcode:
  ```bash  
  xcode-select --install
  ```
  Using Homebrew:
  ```bash  
  brew install make
  ```

### Testing Required Tools

If you have not already done so, clone the repository and navigate there in your command shell.

You can build the main outputs using `make`:

```sh
make build lint
```

Running these steps will run our build and lint steps and verify that the tools are installed correctly. If you get stuck or suspect something is not working in these instructions please ask for help in our [discord](https://discordapp.com/channels/1116864463832891502/11168644638328915074).

### Editor

If you don't have a code editor set up for Go, we recommend VS Code. The experience with VS Code is high-quality and approachable for newcomers.

Alternatively, you can choose whichever editor you are most comfortable for working on Go code. Feel free to skip this section if you want to make another choice.

- [Visual Studio Code](https://code.visualstudio.com/)
- [Go extension](https://marketplace.visualstudio.com/items?itemName=golang.go)

Install both of these and then follow the steps in the *Quick Start* for the Go extension.

The extension will walk you through an automated install of some additional tools that match your installed version of Go.

#### Launching VSCode

The best way to launch VS Code for Go is to do *File* -> *Open Folder* on the repository. 

You can easily do this from the command shell with `code .`, which opens the current directory as a folder in VS Code.

### Additional Tools

#### Test summaries

The default `go test` output can be hard to read when you have many tests. We recommend `gotestsum` as a tool to solve this. Our `make test` command will automatically use `gotestsum` if it is available.

- [gotestsum](https://github.com/gotestyourself/gotestsum#install)

## Building the code

Invisinets uses a Makefile to build the repository and automate most common repository tasks.

You can run `make` (no additional arguments) to see the list of targets and their descriptions.

## Building the repository

You can build the repository with `make build`. This will build all of the packages and executables. The first time you run `make build` it may take a few minutes because it will download and build dependencies. Subsequent builds will be faster because they can use cached output.

The following command will build, run unit tests, and run linters. This command is handy for verifying that your local changes are working correctly.

```sh
make build lint test
```

## Troubleshooting and getting help

You might encounter error messages while running various `make` commands due to missing dependencies. Review the prerequisites listed above for installation instructions.

If you get stuck working with the repository, please ask for help in our [discord](https://discordapp.com/channels/1116864463832891502/11168644638328915074). We're always interested in ways to improve the tooling, so please feel free to report problems and suggest improvements.

If you need to report an issue with the Makefile, we may ask you for a dump of the variables. You can see the state of all of the variables our Makefile defines with `make dump`. The output will be quite large so you might want to redirect this to a file.

## Writing good Go code

### Learning Go

Go is a great language for newcomers! Due to its simple style and uncomplicated design, we find that new contributors can get *going* without a long learning process.

For learning Go, we recommend the following resources:

- [Tour of Go](https://go.dev/tour/welcome/1)
- [Effective Go](https://go.dev/doc/effective_go)
- [Offical tutorials](https://go.dev/doc/)

We're happy to accept pull-requests and give code review feedback aimed at newbies. If you have programmed in other languages before, we are confident you can pick up Go and start contributing easily.

### Asking for help

Get stuck while working on a change? Want to get advice on coding style or existing code? Please ask for help in our [discord](https://discordapp.com/channels/1116864463832891502/11168644638328915074).

### Getting productive

You'll want to run the following command often:

```sh
make build test lint
```

This will build, run unit tests, and run linters to point out any problems. It's a good idea to run this if you're about to make a `git commit`.


### Coding style & linting

We enforce coding style through using [gofmt](https://pkg.go.dev/cmd/gofmt).

We stick to the usual philosophy of Go projects regarding styling, meaning that we prefer to avoid bikeshedding and debates about styling:

>  gofmt isn't anybody's preferred style, but it's adequate for everybody.

If you're using a modern editor with Go support, chances are it is already integrated with `gofmt` and this will mostly be automatic. If there's any question about how to style a piece of code, following the style of the surrounding code is a safe bet. 

---

We also *mostly* agree with [Google's Go Style Guide](https://google.github.io/styleguide/go/), but don't follow it strictly or enforce everything written there. If you're new to working on a Go project, this is a great read that will get you thinking critically about the small decisions you will make when writing Go code. 

### Documentation

One thing we do require is [godoc comments](https://tip.golang.org/doc/comment) on **exported** packages, types, variables, constants, and functions. We like this because it has two good effects:

- Encourages you to minimize the exported surface-area, thus simplifying the design.
- Requires you to document clearly the purpose code you expect other parts of the codebase to call.

Right now we don't have automated enforcement of this rule, so expect it to come up in code review if you forget.


### Linting

We run [golint-ci](https://github.com/golangci/golangci-lint) as part of the pull-request process for static analysis. We don't have many customizations and mostly rely on the defaults.
