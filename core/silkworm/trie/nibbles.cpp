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

Bytes from_nibbles(ByteView data) {
    if (data.empty()) {
        return {};
    }

    size_t pos{data.length() & 1};
    Bytes out((data.length() + pos) / 2, '\0');
    if (pos) {
        out.back() = data.back() << 4;
        data.remove_suffix(1);
    }

    auto out_it{out.begin()};
    while (!data.empty()) {
        *out_it++ = (data[0] << 4) + data[1];
        data.remove_prefix(2);
    }

    return out;
}

Bytes to_nibbles(ByteView data) {
    if (data.empty()) {
        return {};
    }

    Bytes out(2 * data.length(), '\0');
    auto out_it{out.begin()};
    for (const auto& b : data) {
        *out_it++ = b >> 4;
        *out_it++ = b & 0xF;
    }
    return out;
}

}  // namespace silkworm::trie
