##@ Test

# Use gotestsum if available, otherwise use go test. We want to enable testing with just 'make test'
# without external dependencies, but want to use gotestsum in our CI pipelines for the improved
# reporting.
#
# See: https://github.com/gotestyourself/gotestsum
#
# Gotestsum is a drop-in replacement for go test, but it provides a much nicer formatted output
# and it can also generate JUnit XML reports.
ifeq (, $(shell which gotestsum))
GOTEST_TOOL ?= go test
else
# Use these options by default but allow an override via env-var
GOTEST_OPTS ?=
# We need the double dash here to separate the 'gotestsum' options from the 'go test' options
GOTEST_TOOL ?= gotestsum $(GOTESTSUM_OPTS) --
endif

# Optionally test an individual package
INTERNAL_PKG ?= ...
PKG ?= ...

GOTEST_PKG := 
GOTEST_INTERNAL_PKG :=

# Set package directories with explicit conditionals.
ifeq ($(PKG),...)
  GOTEST_PKG =
else
  GOTEST_PKG = ./pkg/$(PKG)
endif

ifeq ($(INTERNAL_PKG),...)
  GOTEST_INTERNAL_PKG =
else
  GOTEST_INTERNAL_PKG = ./internal/$(INTERNAL_PKG)
endif

# If neither directory was set, default to testing all.
ifeq ($(strip $(GOTEST_PKG) $(GOTEST_INTERNAL_PKG)),)
  GOTEST_PKG = ./pkg/...
  GOTEST_INTERNAL_PKG = ./internal/...
endif

# Overriden when running integration tests in CI/CD pipeline
GOTEST_CMD = CGO_ENABLED=1 $(GOTEST_TOOL) -v $(GOTEST_INTERNAL_PKG) $(GOTEST_PKG) $(GOTEST_OPTS)

.PHONY: test
test: ## Runs unit tests in the internal and pkg folders
	$(GOTEST_CMD) -tags=unit

.PHONY: integration-test
integration-test:
	$(GOTEST_CMD) -tags=integration -timeout 70m

.PHONY: azure-integration-test
azure-integration-test:
	$(GOTEST_CMD) -tags=integrationazure -timeout 70m

.PHONY: multicloud-test
multicloud-test:
	$(GOTEST_CMD) -tags=multicloud -timeout 2h
