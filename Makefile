.PHONY: default help fmt lint_copyright lint build run_smoke_tests run_unit_tests test

SILKWORM_BUILD_DIR = build

default: build

help:
	@echo "Targets:"
	@echo "make fmt          - reformat the code"
	@echo "make lint         - run code checks"
	@echo "make build        - build all targets"
	@echo "make test         - run built unit and smoke tests"

fmt:
	@cmake -P cmake/cmake_format.cmake
	@cmake -P cmake/format.cmake

lint_copyright:
	@cmake -P cmake/copyright.cmake

lint: lint_copyright

build:
	@cmake --build $(SILKWORM_BUILD_DIR) --parallel $$(cmake/parallel_jobs_count.sh)

run_smoke_tests:
	@cmake/run_smoke_tests.sh $(SILKWORM_BUILD_DIR)

run_unit_tests:
	@cmake/run_unit_tests.sh $(SILKWORM_BUILD_DIR) $(SILKWORM_CLANG_COVERAGE) $(SILKWORM_SANITIZE) $(SILKWORM_PROJECT_DIR)

test: run_smoke_tests run_unit_tests
