# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

find_package(absl REQUIRED)
find_package(Boost REQUIRED COMPONENTS headers)
find_package(CLI11 REQUIRED)
find_package(tomlplusplus REQUIRED)

add_executable(embed_toml "embed_toml.cpp")
target_link_libraries(embed_toml PRIVATE silkworm_core absl::strings CLI11::CLI11 tomlplusplus::tomlplusplus)

add_executable(embed_json "embed_json.cpp")
target_link_libraries(embed_json PRIVATE silkworm_core CLI11::CLI11 Boost::headers)

add_executable(kzg_g2_uncompress "kzg_g2_uncompress.cpp")
target_link_libraries(kzg_g2_uncompress silkworm_core blst::blst)

add_executable(state_transition "runner.cpp")
target_link_libraries(state_transition PRIVATE silkworm_dev)
file(GLOB STATE_TRANSITION_TESTS CONFIGURE_DEPENDS "state_transition_sample*.json")
add_custom_command(
  TARGET state_transition
  POST_BUILD
  COMMAND ${CMAKE_COMMAND} ARGS -E copy_if_different ${STATE_TRANSITION_TESTS} "${CMAKE_CURRENT_BINARY_DIR}"
)
