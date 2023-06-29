ARROW := \033[34;1m=>\033[0m

# order matters for these
include build/help.mk build/version.mk build/build.mk build/test.mk build/install.mk build/debug.mk
