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

#include "evmc_bytes32.hpp"

#include <algorithm>
#include <cstring>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/rlp/encode.hpp>

namespace silkworm {

evmc::bytes32 to_bytes32(ByteView bytes) {
    evmc::bytes32 out;
    if (!bytes.empty()) {
        size_t n{std::min(bytes.size(), kHashLength)};
        std::memcpy(out.bytes + kHashLength - n, bytes.data(), n);
    }
    return out;
}

std::string to_hex(const evmc::bytes32& value, bool with_prefix) {
    return silkworm::to_hex(ByteView{value.bytes}, with_prefix);
}

}  // namespace silkworm

namespace silkworm::rlp {

void encode(Bytes& to, const evmc::bytes32& value) {
    silkworm::rlp::encode(to, ByteView{value.bytes});
}

size_t length(const evmc::bytes32& value) noexcept {
    return silkworm::rlp::length(ByteView{value.bytes});
}

DecodingResult decode(ByteView& from, evmc::bytes32& to, Leftover mode) noexcept {
    return silkworm::rlp::decode(from, to.bytes, mode);
}

}  // namespace silkworm::rlp
