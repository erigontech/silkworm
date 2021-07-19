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

#include "receipt_cbor.hpp"

#include <cbor/encoder.h>
#include <cbor/output_dynamic.h>

namespace silkworm {

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

        encoder.write_int(static_cast<unsigned>(r.type));
        encoder.write_null();  // no PostState
        encoder.write_int(r.success ? 1u : 0u);
        encoder.write_int(static_cast<unsigned long long>(r.cumulative_gas_used));

        // Bloom filter and logs are omitted, same as in Erigon
    }

    return Bytes{output.data(), output.size()};
}

}  // namespace silkworm
