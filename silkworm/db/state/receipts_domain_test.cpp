// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "receipts_domain.hpp"

#include <catch2/catch_test_macros.hpp>

namespace silkworm::db::state {

TEST_CASE("ReceiptsDomainKeySnapshotsDecoder") {
    ReceiptsDomainKeySnapshotsDecoder decoder;
    BytesOrByteView one{Bytes{1}};
    decoder.decode_word(one);
    CHECK(decoder.value == ReceiptsDomainKey::kCumulativeBlobGasUsedInBlockKey);

    BytesOrByteView empty;
    CHECK_THROWS_AS(decoder.decode_word(empty), std::runtime_error);
}

}  // namespace silkworm::db::state
