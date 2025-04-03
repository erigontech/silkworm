// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
        encoder.write_array(static_cast<int>(v.size()));
    }

    for (const Receipt& r : v) {
        encoder.write_array(4);

        encoder.write_int(static_cast<unsigned>(r.type));
        encoder.write_null();  // no PostState
        encoder.write_int(r.success ? 1u : 0u);
        encoder.write_int(static_cast<unsigned long long>(r.cumulative_gas_used));  // NOLINT(google-runtime-int)

        // Bloom filter and logs are omitted, same as in Erigon
    }

    return Bytes{output.data(), output.size()};
}

}  // namespace silkworm
