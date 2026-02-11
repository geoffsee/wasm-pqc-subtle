# WASM PQC Subtle Build & Optimize

WASM_OPT := $(shell which wasm-opt 2>/dev/null || echo "/Users/williamseemueller/workspace/binaryen-version_123/bin/wasm-opt")

.PHONY: all build optimize clean publish

all: optimize

build:
	wasm-pack build --target web --release

optimize: build
	@echo "Running extra size optimization with wasm-opt -Oz..."
	$(WASM_OPT) -Oz --enable-bulk-memory pkg/wasm_pqc_subtle_bg.wasm -o pkg/wasm_pqc_subtle_bg.wasm
	@echo "Optimized WASM size:"
	@ls -lh pkg/wasm_pqc_subtle_bg.wasm

publish: optimize
	cd pkg && npm publish

clean:
	rm -rf target pkg
