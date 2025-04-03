// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "cached_chain.hpp"

#include <string>

#include <evmc/evmc.hpp>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/db/tables.hpp>

namespace silkworm::rpc::core::rawdb {

static Bytes kNumber{*silkworm::from_hex("00000000003D0900")};
static Bytes kBlockHash{*silkworm::from_hex("439816753229fc0736bf86a5048de4bc9fcdede8c91dadf88c828c76b2281dff")};
static Bytes kHeader{*silkworm::from_hex(
    "f9025ca0209f062567c161c5f71b3f57a7de277b0e95c3455050b152d785ad"
    "7524ef8ee7a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347940000000000000000000000000000000"
    "000000000a0e7536c5b61ed0e0ab7f3ce7f085806d40f716689c0c086676757de401b595658a040be247314d834a319556d1dcf458e87"
    "07cc1aa4a416b6118474ce0c96fccb1aa07862fe11d10a9b237ffe9cb660f31e4bc4be66836c9bfc17310d47c60d75671fb9010000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000001833d0900837a1200831e784b845fe880abb8"
    "61d88301091a846765746888676f312e31352e36856c696e757800000000000000be009d0049d6f0ee8ca6764a1d3eb519bd4d046e167"
    "ddcab467d5db31d063f2d58f266fa86c4502aa169d17762090e92b821843de69b41adbb5d86f5d114ba7f01a000000000000000000000"
    "00000000000000000000000000000000000000000000880000000000000000")};
static Bytes kBody{*silkworm::from_hex("c68369e45a03c0")};
static Bytes kNotEmptyBody{*silkworm::from_hex("c683897f2e04c0")};

#ifdef TEST_DELETED
static void check_expected_block_with_hash(const silkworm::BlockWithHash& bwh) {
    CHECK(bwh.block.header.parent_hash == 0x209f062567c161c5f71b3f57a7de277b0e95c3455050b152d785ad7524ef8ee7_bytes32);
    CHECK(bwh.block.header.ommers_hash == 0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347_bytes32);
    CHECK(bwh.block.header.beneficiary == hex_to_address("0000000000000000000000000000000000000000"));
    CHECK(bwh.block.header.state_root == 0xe7536c5b61ed0e0ab7f3ce7f085806d40f716689c0c086676757de401b595658_bytes32);
    CHECK(bwh.block.header.transactions_root == 0x40be247314d834a319556d1dcf458e8707cc1aa4a416b6118474ce0c96fccb1a_bytes32);
    CHECK(bwh.block.header.receipts_root == 0x7862fe11d10a9b237ffe9cb660f31e4bc4be66836c9bfc17310d47c60d75671f_bytes32);
    CHECK(bwh.block.header.number == 4000000);
    CHECK(bwh.block.header.gas_limit == 8000000);
    CHECK(bwh.block.header.gas_used == 1996875);
    CHECK(bwh.block.header.timestamp == 1609072811);
    CHECK(bwh.block.header.extra_data == *silkworm::from_hex("d88301091a846765746888676f312e31352e36856c696e757800000000000000be009d0049d6f0ee8ca6764a1d3e"
                                                             "b519bd4d046e167ddcab467d5db31d063f2d58f266fa86c4502aa169d17762090e92b821843de69b41adbb5d86f5d114ba7f01"));
    CHECK(bwh.block.header.prev_randao == 0x0000000000000000000000000000000000000000000000000000000000000000_bytes32);
    CHECK(bwh.hash == 0x439816753229fc0736bf86a5048de4bc9fcdede8c91dadf88c828c76b2281dff_bytes32);
}

static void check_expected_transaction(const Transaction& transaction) {
    const auto eth_hash = transaction.hash();
    const auto tx_hash = silkworm::to_bytes32(silkworm::ByteView{eth_hash.bytes, silkworm::kHashLength});
    CHECK(tx_hash == 0x3ff7b8917f1941784c709d6e54db18500fddc2b4c1a90b5cdec675cd0f9fc042_bytes32);
    CHECK(transaction.access_list.empty());
    CHECK(transaction.block_hash == 0x439816753229fc0736bf86a5048de4bc9fcdede8c91dadf88c828c76b2281dff_bytes32);
    CHECK(transaction.block_num == 4'000'000);
    CHECK(transaction.block_base_fee_per_gas == std::nullopt);
    CHECK(transaction.chain_id == 5);
    CHECK(transaction.data == *silkworm::from_hex(
                                  "f2f0387700000000000000000000000000000000000000000000000000000000000158b09f0270fc889c577c1c64db7c819f921d1b6e8c7e5d3f2ff34f162cf4b324cc05"));
    CHECK(transaction.sender() == 0x70A5C9D346416f901826581d423Cd5B92d44Ff5a_address);
    CHECK(transaction.nonce == 103470);
    CHECK(transaction.max_priority_fee_per_gas == 0x77359400);
    CHECK(transaction.max_fee_per_gas == 0x77359400);
    CHECK(transaction.gas_limit == 5000000);
    CHECK(transaction.transaction_index == 0);
    CHECK(transaction.type == TransactionType::kLegacy);
}
#endif

}  // namespace silkworm::rpc::core::rawdb
