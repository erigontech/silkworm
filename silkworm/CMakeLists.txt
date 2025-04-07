# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

# Silkworm itself
add_subdirectory(core)

if(NOT SILKWORM_CORE_ONLY)
  add_subdirectory(interfaces)
  add_subdirectory(infra)
  add_subdirectory(db)
  add_subdirectory(dev)
  add_subdirectory(execution)
  add_subdirectory(rpc)
  add_subdirectory(sentry)
  add_subdirectory(sync)
  add_subdirectory(node)
  add_subdirectory(capi)
endif()

if(SILKWORM_WASM_API)
  add_subdirectory(wasm)
endif()
