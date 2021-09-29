/*
   Copyright 2020-2021 The Silkworm Authors

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

#include "log_cbor.hpp"

#include <cbor/encoder.h>
#include <cbor/output_dynamic.h>

namespace silkworm {

Bytes cbor_encode(const std::vector<Log>& v) {
    cbor::output_dynamic output{};
    cbor::encoder encoder{output};

    encoder.write_array(static_cast<int>(v.size()));

    for (const Log& l : v) {
        encoder.write_array(3);
        encoder.write_bytes(l.address.bytes, kAddressLength);
        encoder.write_array(static_cast<int>(l.topics.size()));
        for (const evmc::bytes32& t : l.topics) {
            encoder.write_bytes(t.bytes, kHashLength);
        }
        encoder.write_bytes(l.data.data(), l.data.size());
    }

    return Bytes{output.data(), output.size()};
}

}  // namespace silkworm
