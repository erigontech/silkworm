.PHONY: help fmt lint lint_copyright

help:
	@echo "Targets:"
	@echo "make fmt          - reformat everything using clang-format"
	@echo "make lint         - run code checks"

fmt:
	@cmake -P cmake/format.cmake

lint_copyright:
	@cmake -P cmake/copyright.cmake

lint: lint_copyright
