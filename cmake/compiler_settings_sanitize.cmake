# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

if(SILKWORM_SANITIZE)
  # cmake-format: off
  set(SILKWORM_SANITIZE_COMPILER_OPTIONS
      -fno-omit-frame-pointer
      -fno-sanitize-recover=all
      -fsanitize=${SILKWORM_SANITIZE}
  )
  # cmake-format: on
endif()
