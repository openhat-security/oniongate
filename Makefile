# OnionGate — common developer entry points
# Run `make help` for the full list.

.PHONY: help setup install deps \
	start dev run build build-frontend preview \
	downloads macos-filter icons \
	check typecheck test lint fmt fmt-check audit \
	changelog-check changelog-sync release-check release-bundle-local sidecar-sbom \
	docs docs-build docs-preview \
	clean clean-rust clean-deps clean-docs cleanup

CARGO_MANIFEST := src-tauri/Cargo.toml
NPM ?= npm

help: ## Show this help
	@printf 'OnionGate targets\n\n'
	@awk 'BEGIN {FS = ":.*## "}; /^[a-zA-Z0-9_-]+:.*## / {printf "  %-18s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ---------------------------------------------------------------------------
# Install from source
# ---------------------------------------------------------------------------

setup: ## Install npm deps and fetch verified Tor / sing-box sidecars
	$(NPM) ci
	$(NPM) run deps

install: setup ## Alias for setup (install from source)

deps: ## Download + SHA-256-verify bundled Tor / lyrebird / sing-box
	$(NPM) run deps

# ---------------------------------------------------------------------------
# Develop / run
# ---------------------------------------------------------------------------

start: deps ## Start daemons, then Tauri dev (see docs/guide/daemons.md)
	bash scripts/dev.sh

dev: start ## Alias for start

run: start ## Alias for start

cleanup: ## Restore host network defaults after a killed session
	bash scripts/dev-cleanup.sh

preview: ## Serve the built frontend (vite preview)
	$(NPM) run preview

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

macos-filter: ## Compile the macOS connection-filter system extension (needs Xcode + a Developer ID profile to load)
	$(MAKE) -C macos/OnionGateFilter

build: deps ## Build a release app bundle (Tauri)
	$(NPM) run tauri build
	@if [ "$$(uname -s)" = Darwin ]; then \
		$(MAKE) macos-filter || true; \
		for app in src-tauri/target/release/bundle/macos/*.app; do \
			[ -d "$$app" ] && bash scripts/embed-oniongate-filter.sh "$$app" || true; \
		done; \
	fi

downloads: release-bundle-local ## Build local installer/download files for this OS

build-frontend: ## Typecheck and build the Vite frontend only
	$(NPM) run build

icons: ## Clean logo transparency and regenerate platform icon bundles (macOS)
	@command -v swift >/dev/null || { echo "Swift is required for icon generation"; exit 1; }
	swift scripts/generate-icons.swift
	$(NPM) run tauri -- icon public/logo.png
	rm -rf src-tauri/icons/android src-tauri/icons/ios

# ---------------------------------------------------------------------------
# Quality
# ---------------------------------------------------------------------------

check: changelog-check ## Typecheck frontend + run Rust tests + changelog trail
	$(NPM) run check

changelog-sync: ## Copy CHANGELOG.md into docs and write the commit-subject audit page
	node scripts/sync-release-docs.mjs

changelog-check: ## Require changelog bullets and in-sync docs pages
	node --test scripts/check-changelog.test.mjs
	node scripts/check-changelog.mjs

typecheck: ## TypeScript check (no emit)
	$(NPM) run typecheck

test: ## Run Rust tests
	cargo test --manifest-path $(CARGO_MANIFEST)

lint: ## Clippy (all targets) + rustfmt check
	$(NPM) run lint:rust
	$(NPM) run fmt:check

fmt: ## Format Rust sources
	cargo fmt --manifest-path $(CARGO_MANIFEST) --all

fmt-check: ## Check Rust formatting without writing
	$(NPM) run fmt:check

audit: ## cargo audit against src-tauri/Cargo.lock
	cargo audit --file src-tauri/Cargo.lock

release-check: changelog-check ## Validate version sync, CHANGELOG, and docs trail (VERSION=x.y.z optional)
	node scripts/check-release.mjs $(VERSION)

release-bundle-local: ## Build and verify an unsigned bundle for this host
	bash scripts/build-release-local.sh

sidecar-sbom: ## Generate CycloneDX inventory for pinned runtime archives
	node scripts/generate-sidecar-sbom.mjs sidecars.cdx.json

# ---------------------------------------------------------------------------
# Documentation site
# ---------------------------------------------------------------------------

docs: ## Serve the documentation site with hot reload
	$(NPM) run docs:dev

docs-build: ## Build the documentation site into docs/.vitepress/dist
	$(NPM) run docs:build

docs-preview: docs-build ## Preview the built documentation site
	$(NPM) run docs:preview

# ---------------------------------------------------------------------------
# Clean
# ---------------------------------------------------------------------------

clean: clean-rust ## Remove Rust build artifacts
	@echo "Done. (node_modules and .deps-cache kept; use clean-deps to drop sidecars)"

clean-rust: ## cargo clean for src-tauri
	$(NPM) run clean:rust

clean-deps: ## Remove downloaded sidecars and the deps cache
	rm -rf .deps-cache
	find src-tauri/binaries -mindepth 1 -maxdepth 1 ! -name 'README.md' -exec rm -rf {} +
	rm -rf src-tauri/resources/runtime

clean-docs: ## Remove the documentation site build output and cache
	rm -rf docs/.vitepress/dist docs/.vitepress/cache
