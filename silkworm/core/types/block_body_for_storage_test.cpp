// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "block_body_for_storage.hpp"

#include <catch2/catch_test_macros.hpp>

namespace silkworm {

TEST_CASE("BlockBodyForStorage encoding") {
    BlockHeader header{
        .parent_hash = 0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c_bytes32,
        .ommers_hash = 0x474f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126d_bytes32,
        .beneficiary = 0x0715a7794a1dc8e42615f059dd6e406a6594651a_address,
        .state_root = 0xb02a3b0ee16c858afaa34bcd6770b3c20ee56aa2f75858733eb0e927b5b7126d_bytes32,
        .transactions_root = 0xb02a3b0ee16c858afaa34bcd6770b3c20ee56aa2f75858733eb0e927b5b7126e_bytes32,
        .receipts_root = 0xb02a3b0ee16c858afaa34bcd6770b3c20ee56aa2f75858733eb0e927b5b7126f_bytes32,
        .difficulty = 1234,
        .number = 5,
        .gas_limit = 1000000,
        .gas_used = 1000000,
        .timestamp = 5405021,
        .extra_data = *from_hex("0001FF0100"),
        .prev_randao = 0x0000000000000000000000000000000000000000000000000000000000000001_bytes32,
        .nonce = {0, 0, 0, 0, 0, 0, 0, 255},
        .base_fee_per_gas = 0x244428,
    };

    // No withdrawals
    BlockBodyForStorage body{.base_txn_id = 15, .txn_count = 3, .ommers = {header}};
    Bytes encoded{body.encode()};
    ByteView view{encoded};
    auto decoded = decode_stored_block_body(view);
    REQUIRE(decoded.has_value());
    CHECK(*decoded == body);

    // With withdrawals
    body.ommers.clear();  // no uncles after The Merge
    body.withdrawals = {{
        .index = 4,
        .validator_index = 1568,
        .address = 0x6295ee1b4f6dd65047762f924ecd367c17eabf8f_address,
        .amount = 786,
    }};
    encoded = body.encode();
    view = encoded;
    decoded = decode_stored_block_body(view);
    REQUIRE(decoded.has_value());
    CHECK(*decoded == body);
}

}  // namespace silkworm
