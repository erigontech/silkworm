// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wshadow"
#include <glaze/glaze.hpp>
#pragma GCC diagnostic pop

#include <nlohmann/json.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/rpc/types/error.hpp>

namespace silkworm::rpc {

inline constexpr std::string_view kJsonVersion{"2.0"};
inline constexpr size_t kAddressHexSize = 2 + 2 * kAddressLength + 1;
inline constexpr size_t kHashHexSize = 2 + 2 * kHashLength + 1;
inline constexpr size_t kBloomSize = 1024;
inline constexpr size_t kInt64HexSize = 2 + 2 * sizeof(uint64_t) + 1;
inline constexpr size_t kInt256HexSize = 2 + 2 * sizeof(intx::uint256) + 1;
inline constexpr size_t kDataSize = 16384;
inline constexpr size_t kEthCallResultFixedSize = 2048;

void make_glaze_json_error(const nlohmann::json& request, int error_id, const std::string& message, std::string& reply);
void make_glaze_json_error(const nlohmann::json& request, const RevertError& error, std::string& reply);

}  // namespace silkworm::rpc
