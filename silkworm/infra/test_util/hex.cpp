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

#include "hex.hpp"

#include <optional>
#include <stdexcept>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/common/util.hpp>

namespace silkworm::test_util {

std::string ascii_from_hex(std::string_view hex) {
    const std::optional<Bytes> bytes{from_hex(hex)};
    if (!bytes) {
        throw std::runtime_error{"ascii_from_hex"};
    }
    return std::string{byte_view_to_string_view(*bytes)};
}

}  // namespace silkworm::test_util
