.PHONY: help fmt lint lint_copyright run_smoke_tests run_unit_tests test

help:
	@echo "Targets:"
	@echo "make fmt          - reformat the code"
	@echo "make lint         - run code checks"
	@echo "make test         - run built unit tests"

fmt:
	@cmake -P cmake/cmake_format.cmake
	@cmake -P cmake/format.cmake

lint_copyright:
	@cmake -P cmake/copyright.cmake

lint: lint_copyright

run_smoke_tests:
	@cmake/run_smoke_tests.sh $(SILKWORM_BUILD_DIR)

run_unit_tests:
	@cmake/run_unit_tests.sh $(SILKWORM_BUILD_DIR) $(SILKWORM_CLANG_COVERAGE)

test: run_smoke_tests run_unit_tests
