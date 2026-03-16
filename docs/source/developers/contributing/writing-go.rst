.. _writinggo:

Writing Good Go Code
--------------------

Learning Go
^^^^^^^^^^^^^^^^^^^^
Go is a great language for newcomers! Due to its simple style and uncomplicated design, we find that new contributors can get *going* without a long learning process.

For learning Go, we recommend the following resources:

- `Tour of Go <https://go.dev/tour/welcome/1>`_
- `Effective Go <https://go.dev/doc/effective_go>`_
- `Offical tutorials <https://go.dev/doc/>`_

We're happy to accept pull-requests and give code review feedback aimed at newbies. If you have programmed in other languages before, we are confident you can pick up Go and start contributing easily.

Coding style
^^^^^^^^^^^^^^^^^^^^^^
We enforce coding style through using `gofmt <https://pkg.go.dev/cmd/gofmt>`_.

We stick to the usual philosophy of Go projects regarding styling, meaning that we prefer to avoid bikeshedding and debates about styling:

    gofmt isn't anybody's preferred style, but it's adequate for everybody.

If you're using a modern editor with Go support, chances are it is already integrated with ``gofmt`` and this will mostly be automatic. 
If there's any question about how to style a piece of code, following the style of the surrounding code is a safe bet. 

We also *mostly* agree with `Google's Go Style Guide <https://google.github.io/styleguide/go/>`_, but don't follow it strictly or enforce everything written there. 
If you're new to working on a Go project, this is a great read that will get you thinking critically about the small decisions you will make when writing Go code. 

Linting
^^^^^^^^^^^^^^^^^^^^
We run `golint-ci <https://github.com/golangci/golangci-lint>`_ as part of the pull-request process for static analysis. 
We don't have many customizations and mostly rely on the defaults.
