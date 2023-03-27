.PHONY: help fmt lint lint_copyright

help:
	@echo "Targets:"
	@echo "make fmt          - reformat the code"
	@echo "make lint         - run code checks"

fmt:
	@cmake -P cmake/cmake_format.cmake
	@cmake -P cmake/format.cmake

lint_copyright:
	@cmake -P cmake/copyright.cmake

lint: lint_copyright
