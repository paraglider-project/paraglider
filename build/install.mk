##@ Install

INV_LOCATION := /usr/local/bin/inv
INVD_LOCATION := /usr/local/bin/invd

.PHONY: install
install: build-binaries ## Installs a local build for development
	@echo "$(ARROW) Installing inv"
	cp $(OUT_DIR)/$(GOOS)_$(GOARCH)/$(BUILDTYPE_DIR)/inv$(BINARY_EXT) $(INV_LOCATION)
	@echo "$(ARROW) Installing invd"
	cp $(OUT_DIR)/$(GOOS)_$(GOARCH)/$(BUILDTYPE_DIR)/invd$(BINARY_EXT) $(INVD_LOCATION)