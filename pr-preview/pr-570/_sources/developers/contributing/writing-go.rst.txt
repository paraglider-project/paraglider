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

Asking for help
^^^^^^^^^^^^^^^^^^^^
Get stuck while working on a change? Want to get advice on coding style or existing code? Please raise an issue or ask for help in our Discord (linked on our homepage).

Getting productive
^^^^^^^^^^^^^^^^^^^^
You'll want to run the following command often:

.. code-block:: console

    $ make build test lint

This will build, run unit tests, and run linters to point out any problems. It's a good idea to run this if you're about to make a ``git commit``.

Coding style
^^^^^^^^^^^^^^^^^^^^^^
We enforce coding style through using `gofmt <https://pkg.go.dev/cmd/gofmt>`_.

We stick to the usual philosophy of Go projects regarding styling, meaning that we prefer to avoid bikeshedding and debates about styling:

    gofmt isn't anybody's preferred style, but it's adequate for everybody.

If you're using a modern editor with Go support, chances are it is already integrated with ``gofmt`` and this will mostly be automatic. 
If there's any question about how to style a piece of code, following the style of the surrounding code is a safe bet. 

We also *mostly* agree with `Google's Go Style Guide <https://google.github.io/styleguide/go/>`_, but don't follow it strictly or enforce everything written there. 
If you're new to working on a Go project, this is a great read that will get you thinking critically about the small decisions you will make when writing Go code. 

Documentation
^^^^^^^^^^^^^^^^^^^^
One thing we do require is `godoc comments <https://tip.golang.org/doc/comment>`_ on **exported** packages, types, variables, constants, and functions. We like this because it has two good effects:

- Encourages you to minimize the exported surface-area, thus simplifying the design.
- Requires you to document clearly the purpose code you expect other parts of the codebase to call.

Right now we don't have automated enforcement of this rule, so expect it to come up in code review if you forget.

Linting
^^^^^^^^^^^^^^^^^^^^
We run `golint-ci <https://github.com/golangci/golangci-lint>`_ as part of the pull-request process for static analysis. 
We don't have many customizations and mostly rely on the defaults.
