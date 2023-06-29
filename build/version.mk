# Commit and release info gets compiled into the binary at build time.
GIT_COMMIT  = $(shell git rev-list -1 HEAD)
GIT_VERSION = $(shell git describe --always --abbrev=7 --dirty --tags)
REL_VERSION ?= latest
REL_CHANNEL ?= latest

# These flags are passed to the linker and will configure the version information in the build.
VERSION_LD_FLAGS = -X $(BASE_PACKAGE_NAME)/internal/version.channel=$(REL_CHANNEL) 
VERSION_LD_FLAGS += -X $(BASE_PACKAGE_NAME)/internal/version.release=$(REL_VERSION) 
VERSION_LD_FLAGS += -X $(BASE_PACKAGE_NAME)/internal/version.commit=$(GIT_COMMIT) 
VERSION_LD_FLAGS += -X $(BASE_PACKAGE_NAME)/internal/version.version=$(GIT_VERSION) 