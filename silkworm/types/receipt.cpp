/*
   Copyright 2020 The Silkworm Authors

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

#include "receipt.hpp"

#include <silkworm/rlp/encode.hpp>

namespace silkworm::rlp {

static Header header(const Receipt& r, bool for_storage) {
    Header h;
    h.list = true;
    h.payload_length = 1;
    h.payload_length += length(r.cumulative_gas_used);
    if (!for_storage) {
        h.payload_length += length(full_view(r.bloom));
    }
    h.payload_length += length(r.logs);
    return h;
}

void encode(Bytes& to, const Receipt& r, bool for_storage) {
    encode_header(to, header(r, for_storage));
    encode(to, r.success);
    encode(to, r.cumulative_gas_used);
    if (!for_storage) {
        encode(to, full_view(r.bloom));
    }
    encode(to, r.logs);
}

Bytes encode_for_storage(const std::vector<Receipt>& v) {
    bool for_storage{true};
    Bytes to{};
    Header h1{/*list=*/true, 0};
    for (const Receipt& x : v) {
        Header h2{header(x, for_storage)};
        h1.payload_length += length_of_length(h2.payload_length) + h2.payload_length;
    }
    encode_header(to, h1);
    for (const Receipt& x : v) {
        encode(to, x, for_storage);
    }
    return to;
}

}  // namespace silkworm::rlp
