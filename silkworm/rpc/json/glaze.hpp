/*
   Copyright 2023 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

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
inline constexpr auto kAddressHexSize = 2 + 2 * kAddressLength + 1;
inline constexpr auto kHashHexSize = 2 + 2 * kHashLength + 1;
inline constexpr auto kBloomSize = 1024;
inline constexpr auto kInt64HexSize = 2 + 2 * sizeof(uint64_t) + 1;
inline constexpr auto kInt256HexSize = 2 + 2 * sizeof(intx::uint256) + 1;
inline constexpr auto kDataSize = 4096;
inline constexpr auto kEthCallResultFixedSize = 2048;

void make_glaze_json_error(const nlohmann::json& request_json, int error_id, const std::string& message, std::string& reply);
void make_glaze_json_error(const nlohmann::json& request_json, const RevertError& error, std::string& reply);

}  // namespace silkworm::rpc
