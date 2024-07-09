BASE_PACKAGE_NAME := github.com/paraglider-project/paraglider
OUT_DIR := ./dist
IMAGE_VERSION ?= latest
IMAGE_ORG ?= paraglider-project
IMAGE_BASE ?= ghcr.io/$(IMAGE_ORG)

GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
GOPATH := $(shell go env GOPATH)
PLATFORMS ?= $(GOOS)/$(GOARCH)

ifeq (,$(shell go env GOBIN))
	GOBIN=$(shell go env GOPATH)/bin
else
	GOBIN=$(shell go env GOBIN)
endif

ifeq ($(GOOS),windows)
   BINARY_EXT = .exe
   GOLANGCI_LINT:=golangci-lint.exe
else
   GOLANGCI_LINT:=golangci-lint
endif

ifeq ($(origin DEBUG), undefined)
  BUILDTYPE_DIR:=release
  GCFLAGS:=""
else ifeq ($(DEBUG),0)
  BUILDTYPE_DIR:=release
  GCFLAGS:=""
else
  BUILDTYPE_DIR:=debug
  GCFLAGS:="all=-N -l"
endif

LDFLAGS := "-s -w $(VERSION_LD_FLAGS)"
GOARGS := -v -gcflags $(GCFLAGS) -ldflags $(LDFLAGS)

export BUILDX_NO_DEFAULT_ATTESTATIONS := 1# Disable default attestations during Docker builds to prevent "unknown/unknown" image in ghcr.
export GO111MODULE ?= on
export GOPROXY ?= https://proxy.golang.org
export GOSUMDB ?= sum.golang.org
export CGO_ENABLED=0

PROTOFILES := $(shell find . -type f -name '*.proto')

##@ Build

.PHONY: build
build: protoc build-packages build-binaries ## Build all go targets.

.PHONY: protoc
protoc: ## Compiles all proto files.
	@echo "$(ARROW) Compiling all proto files"
	@export PATH=$(GOPATH)/bin:$$PATH;$(foreach file,$(PROTOFILES),echo "compiling $(file)" & protoc --go_out=$(dir $(file)) \
	--go_opt=paths=source_relative --go-grpc_out=$(dir $(file))  --go-grpc_opt=paths=source_relative \
	--proto_path=$(dir $(file)) $(file);)
	
.PHONY: build-packages
build-packages: ## Builds all go packages.
	@echo "$(ARROW) Building all packages"
	go build \
		-v \
		-gcflags $(GCFLAGS) \
		-ldflags=$(LDFLAGS) \
		./...

# Generate a target for each binary we define
# Params:
# $(1): the binary name for the target
# $(2): the binary main directory
define generateBuildTarget
.PHONY: build-$(1)
build-$(1): build-$(1)-$(GOOS)-$(GOARCH)
endef

# Generate a target for each binary we define
# Params:
# $(1): the OS
# $(2): the ARCH
# $(3): the binary name for the target
# $(4): the binary main directory
define generatePlatformBuildTarget
.PHONY: build-$(3)-$(1)-$(2)
build-$(3)-$(1)-$(2):
  $(eval BINS_OUT_DIR_$(1)_$(2) := $(OUT_DIR)/$(1)_$(2)/$(BUILDTYPE_DIR))
	@echo "$(ARROW) Building $(3) on $(1)/$(2) to $(BINS_OUT_DIR_$(1)_$(2))/$(3)$(BINARY_EXT)"
	GOOS=$(1) GOARCH=$(2) go build \
		-v \
		-gcflags $(GCFLAGS) \
		-ldflags=$(LDFLAGS) \
		-o $(BINS_OUT_DIR_$(1)_$(2))/$(3)$(BINARY_EXT) \
		$(4)/
endef

# defines a target for each binary
GOOSES := darwin linux windows
GOARCHES := amd64 arm arm64
BINARIES := glide glided
$(foreach ITEM,$(BINARIES),$(eval $(call generateBuildTarget,$(ITEM),./cmd/$(ITEM))))
$(foreach ARCH,$(GOARCHES),$(foreach OS,$(GOOSES),$(foreach ITEM,$(BINARIES),$(eval $(call generatePlatformBuildTarget,$(OS),$(ARCH),$(ITEM),./cmd/$(ITEM))))))

# list of 'outputs' to build for all binaries
BINARY_TARGETS:=$(foreach ITEM,$(BINARIES),build-$(ITEM))

.PHONY: build-binaries
build-binaries: $(BINARY_TARGETS) ## Builds all go binaries.

push-image: build-binaries
	docker buildx build --platform $(PLATFORMS) --progress=plain --rm --tag $(IMAGE_BASE)/paraglider:$(IMAGE_VERSION) --push -f ./Dockerfile .

.PHONY: clean
clean: ## Cleans output directory.
	@echo "$(ARROW) Cleaning all $(OUT_DIR)"
	rm -rf $(OUT_DIR)

# Due to https://github.com/golangci/golangci-lint/issues/580, we need to add --fix for windows
.PHONY: lint 
lint: protoc ## Runs golangci-lint
	$(GOLANGCI_LINT) run --fix --timeout 5m

