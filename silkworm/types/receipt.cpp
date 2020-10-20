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

#include <silkworm/common/util.hpp>
#include <silkworm/rlp/encode.hpp>

#include "cbor-cpp/src/encoder.h"
#include "cbor-cpp/src/output_dynamic.h"

namespace silkworm {

namespace rlp {

    static Header header(const Receipt& r) {
        Header h;
        h.list = true;
        h.payload_length = 1;
        h.payload_length += length(r.cumulative_gas_used);
        h.payload_length += length(full_view(r.bloom));
        h.payload_length += length(r.logs);
        return h;
    }

    void encode(Bytes& to, const Receipt& r) {
        encode_header(to, header(r));
        encode(to, r.success);
        encode(to, r.cumulative_gas_used);
        encode(to, full_view(r.bloom));
        encode(to, r.logs);
    }

}  // namespace rlp

Bytes cbor_encode(const std::vector<Receipt>& v) {
    cbor::output_dynamic output{};
    cbor::encoder encoder{output};

    if (v.empty()) {
        encoder.write_null();
    } else {
        encoder.write_array(v.size());
    }

    for (const Receipt& r : v) {
        encoder.write_array(4);

        encoder.write_null();  // no PostState
        encoder.write_uint(r.success ? 1u : 0u);
        encoder.write_uint(r.cumulative_gas_used);

        if (r.logs.empty()) {
            encoder.write_null();
        } else {
            encoder.write_array(r.logs.size());
        }

        for (const Log& l : r.logs) {
            encoder.write_array(3);
            encoder.write_bytes(l.address.bytes, kAddressLength);
            encoder.write_array(l.topics.size());
            for (const evmc::bytes32& t : l.topics) {
                encoder.write_bytes(t.bytes, kHashLength);
            }
            encoder.write_bytes(l.data.data(), l.data.size());
        }
    }

    return Bytes{output.data(), output.size()};
}

}  // namespace silkworm
