/*
   Copyright 2024 The Silkworm Authors

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

#include <string_view>
#include <vector>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/common/util.hpp>

namespace silkworm::rpc {

inline void deserialize_hex_as_bytes(std::string_view hex, std::vector<Bytes>& sequence) {
    auto bytes{from_hex(hex)};
    if (bytes) {
        sequence.push_back(std::move(*bytes));
    }
}

}  // namespace silkworm::rpc
