##@ Install

GLIDE_LOCATION := /usr/local/bin/glide
GLIDED_LOCATION := /usr/local/bin/glided

.PHONY: install
install: build-binaries ## Installs a local build for development
	@echo "$(ARROW) Installing glide"
	sudo cp $(OUT_DIR)/$(GOOS)_$(GOARCH)/$(BUILDTYPE_DIR)/glide$(BINARY_EXT) $(GLIDE_LOCATION)
	@echo "$(ARROW) Installing glided"
	sudo cp $(OUT_DIR)/$(GOOS)_$(GOARCH)/$(BUILDTYPE_DIR)/glided$(BINARY_EXT) $(GLIDED_LOCATION)
