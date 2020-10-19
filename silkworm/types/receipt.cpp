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

#include <nlohmann/json.hpp>
#include <silkworm/common/util.hpp>
#include <silkworm/rlp/encode.hpp>

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

std::vector<uint8_t> cbor_encode(const std::vector<Receipt>& v) {
    using namespace nlohmann;

    // BinaryType = Bytes
    using BytesJson = basic_json<std::map, std::vector, std::string, bool, std::int64_t, std::uint64_t, double,
                                 std::allocator, adl_serializer, Bytes>;

    BytesJson json{};

    for (const Receipt& r : v) {
        BytesJson receipt{};

        receipt.push_back(nullptr);  // no PostState
        receipt.push_back(r.success ? 1u : 0u);
        receipt.push_back(r.cumulative_gas_used);

        BytesJson logs{};
        for (const Log& l : r.logs) {
            BytesJson log{};
            log.push_back(BytesJson::binary(Bytes{full_view(l.address)}));
            BytesJson topics = BytesJson::array();
            for (const evmc::bytes32& t : l.topics) {
                topics.push_back(BytesJson::binary(Bytes{full_view(t)}));
            }
            log.push_back(topics);
            log.push_back(BytesJson::binary(l.data));
            logs.push_back(log);
        }
        receipt.push_back(logs);

        json.push_back(receipt);
    }

    return BytesJson::to_cbor(json);
}

}  // namespace silkworm
