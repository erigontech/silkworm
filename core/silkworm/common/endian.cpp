/*
   Copyright 2021 The Silkworm Authors

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

#include "endian.hpp"

#include <silkworm/common/util.hpp>

namespace silkworm::endian {

Bytes to_big_compact(const uint64_t value) {
    if (!value) {
        return {};  // All bytes are zero
    }
    thread_local Bytes be(8, '\0');
    endian::store_big_u64(&be[0], value);
    return Bytes{zeroless_view(be)};
}

std::optional<uint64_t> from_big_compact(const ByteView& data) {
    // Important ! We can't have a string of bytes wider than an uint64_t
    if (data.length() > sizeof(uint64_t)) {
        return std::nullopt;
    }

    uint64_t ret{0};
    if (data.empty()) {
        return ret;
    }

    uint8_t num_shifts{0};
    for (auto i = data.rbegin(); i != data.rend(); ++i) {
        ret |= (static_cast<uint64_t>(*i) << num_shifts);
        num_shifts += 8;
    }
    return ret;
}

}  // namespace silkworm::endian
