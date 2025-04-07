# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

file(GLOB STUN_MSG_SRC "stun-msg/src/*.*")
add_library(stun_msg "${STUN_MSG_SRC}")
target_include_directories(stun_msg PUBLIC "stun-msg/include")
target_compile_options(stun_msg PRIVATE -w) # disable warnings
