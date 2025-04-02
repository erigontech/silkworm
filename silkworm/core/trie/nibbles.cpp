/*
   Copyright 2022 The Silkworm Authors

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

#include "nibbles.hpp"

namespace silkworm::trie {

Bytes pack_nibbles(ByteView unpacked) {
    if (unpacked.empty()) {
        return {};
    }

    size_t pos{unpacked.size() & 1};
    Bytes out((unpacked.size() + pos) / 2, '\0');
    auto out_it{out.begin()};
    while (unpacked.size() > pos) {
        *out_it++ = static_cast<uint8_t>((unpacked[0] << 4) + unpacked[1]);
        unpacked.remove_prefix(2);
    }
    if (pos) {
        *out_it = static_cast<uint8_t>(unpacked[0] << 4);
        unpacked.remove_prefix(1);
    }

    return out;
}

Bytes unpack_nibbles(ByteView data) {
    Bytes out(2 * data.size(), '\0');
    size_t offset{0};
    for (const auto& b : data) {
        out[offset] = b >> 4;
        out[offset + 1] = b & 0x0F;
        offset += 2;
    }
    return out;
}

}  // namespace silkworm::trie
