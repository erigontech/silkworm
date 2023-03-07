/*
   Copyright 2021 The Silkrpc Authors

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

#include <string>

#include <silkworm/silkrpc/config.hpp> // NOLINT(build/include_order)

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/use_future.hpp>
#include <evmc/evmc.hpp>
#include <gmock/gmock.h>
#include <nlohmann/json.hpp>

#include <silkworm/silkrpc/concurrency/context_pool.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/common/base.hpp>
#include <silkworm/core/chain/config.hpp>
#include <silkworm/node/common/log.hpp>

#include <silkworm/silkrpc/common/log.hpp>
#include <silkworm/silkrpc/core/blocks.hpp>
#include <silkworm/silkrpc/core/rawdb/accessors.hpp>
#include <silkworm/silkrpc/core/rawdb/chain.hpp>
#include <silkworm/silkrpc/ethdb/tables.hpp>
#include <silkworm/silkrpc/types/block.hpp>
#include <silkworm/silkrpc/types/chain_config.hpp>
#include <silkworm/silkrpc/types/receipt.hpp>

#include "cached_chain.hpp"

#include <catch2/catch.hpp>

namespace silkrpc::core::rawdb {
using testing::DoAll;
using testing::Invoke;
using testing::InvokeWithoutArgs;
using testing::Return;
using testing::Unused;
using testing::_;
using evmc::literals::operator""_address;
using evmc::literals::operator""_bytes32;

using Catch::Matchers::Message;
using evmc::literals::operator""_address, evmc::literals::operator""_bytes32;

static silkworm::Bytes kNumber{*silkworm::from_hex("00000000003D0900")};
static silkworm::Bytes kBlockHash{*silkworm::from_hex("439816753229fc0736bf86a5048de4bc9fcdede8c91dadf88c828c76b2281dff")};
static silkworm::Bytes kHeader{*silkworm::from_hex("f9025ca0209f062567c161c5f71b3f57a7de277b0e95c3455050b152d785ad"
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
static silkworm::Bytes kBody{*silkworm::from_hex("c68369e45a03c0")};
static silkworm::Bytes kNotEmptyBody{*silkworm::from_hex("c683897f2e04c0")};


static void check_expected_block_with_hash(const silkworm::BlockWithHash& bwh) {
    CHECK(bwh.block.header.parent_hash == 0x209f062567c161c5f71b3f57a7de277b0e95c3455050b152d785ad7524ef8ee7_bytes32);
    CHECK(bwh.block.header.ommers_hash == 0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347_bytes32);
    CHECK(bwh.block.header.beneficiary == silkworm::to_evmc_address(*silkworm::from_hex("0000000000000000000000000000000000000000")));
    CHECK(bwh.block.header.state_root == 0xe7536c5b61ed0e0ab7f3ce7f085806d40f716689c0c086676757de401b595658_bytes32);
    CHECK(bwh.block.header.transactions_root == 0x40be247314d834a319556d1dcf458e8707cc1aa4a416b6118474ce0c96fccb1a_bytes32);
    CHECK(bwh.block.header.receipts_root == 0x7862fe11d10a9b237ffe9cb660f31e4bc4be66836c9bfc17310d47c60d75671f_bytes32);
    CHECK(bwh.block.header.number == 4000000);
    CHECK(bwh.block.header.gas_limit == 8000000);
    CHECK(bwh.block.header.gas_used == 1996875);
    CHECK(bwh.block.header.timestamp == 1609072811);
    CHECK(bwh.block.header.extra_data == *silkworm::from_hex("d88301091a846765746888676f312e31352e36856c696e757800000000000000be009d0049d6f0ee8ca6764a1d3e"
        "b519bd4d046e167ddcab467d5db31d063f2d58f266fa86c4502aa169d17762090e92b821843de69b41adbb5d86f5d114ba7f01"));
    CHECK(bwh.block.header.mix_hash == 0x0000000000000000000000000000000000000000000000000000000000000000_bytes32);
    CHECK(bwh.hash == 0x439816753229fc0736bf86a5048de4bc9fcdede8c91dadf88c828c76b2281dff_bytes32);
}

static void check_expected_transaction(const Transaction& transaction) {
    const auto eth_hash = hash_of_transaction(transaction);
    const auto tx_hash = silkworm::to_bytes32(silkworm::ByteView{eth_hash.bytes, silkworm::kHashLength});
    CHECK(tx_hash == 0x3ff7b8917f1941784c709d6e54db18500fddc2b4c1a90b5cdec675cd0f9fc042_bytes32);
    CHECK(transaction.access_list.empty());
    CHECK(transaction.block_hash == 0x439816753229fc0736bf86a5048de4bc9fcdede8c91dadf88c828c76b2281dff_bytes32);
    CHECK(transaction.block_number == 4'000'000);
    CHECK(transaction.block_base_fee_per_gas == std::nullopt);
    CHECK(transaction.chain_id == 5);
    CHECK(transaction.data == *silkworm::from_hex(
        "f2f0387700000000000000000000000000000000000000000000000000000000000158b09f0270fc889c577c1c64db7c819f921d1b6e8c7e5d3f2ff34f162cf4b324cc05"));
    CHECK(*transaction.from == 0x70A5C9D346416f901826581d423Cd5B92d44Ff5a_address);
    CHECK(transaction.nonce == 103470);
    CHECK(transaction.max_priority_fee_per_gas == 0x77359400);
    CHECK(transaction.max_fee_per_gas == 0x77359400);
    CHECK(transaction.gas_limit == 5000000);
    CHECK(transaction.transaction_index == 0);
    CHECK(transaction.type == Transaction::Type::kLegacy);
}


class MockDatabaseReader : public rawdb::DatabaseReader {
public:
    MOCK_CONST_METHOD2(get, boost::asio::awaitable<KeyValue>(const std::string&, const silkworm::ByteView&));
    MOCK_CONST_METHOD2(get_one, boost::asio::awaitable<silkworm::Bytes>(const std::string&, const silkworm::ByteView&));
    MOCK_CONST_METHOD3(get_both_range, boost::asio::awaitable<std::optional<silkworm::Bytes>>(const std::string&, const silkworm::ByteView&, const silkworm::ByteView&));
    MOCK_CONST_METHOD4(walk, boost::asio::awaitable<void>(const std::string&, const silkworm::ByteView&, uint32_t, Walker));
    MOCK_CONST_METHOD3(for_prefix, boost::asio::awaitable<void>(const std::string&, const silkworm::ByteView&, Walker));
};

TEST_CASE("read_block_by_number_or_hash") {
    boost::asio::thread_pool pool{1};
    MockDatabaseReader db_reader;
    BlockCache cache(10, true);

    SECTION("using valid number") {
        BlockNumberOrHash bnoh{4'000'000};
        EXPECT_CALL(db_reader, get_one(db::table::kCanonicalHashes, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return kBlockHash; }
        ));
        EXPECT_CALL(db_reader, get_one(db::table::kHeaders, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return kHeader; }
        ));
        EXPECT_CALL(db_reader, get_one(db::table::kBlockBodies, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return kBody; }
        ));
        EXPECT_CALL(db_reader, walk(db::table::kEthTx, _, _, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<void> { co_return; }
        ));
        auto result = boost::asio::co_spawn(pool, read_block_by_number_or_hash(cache, db_reader, bnoh), boost::asio::use_future);
        const silkworm::BlockWithHash bwh = result.get();
        check_expected_block_with_hash(bwh);
    }

    SECTION("using valid hash") {
        BlockNumberOrHash bnoh{"0x439816753229fc0736bf86a5048de4bc9fcdede8c91dadf88c828c76b2281dff"};
        BlockCache cache(10, true);

        EXPECT_CALL(db_reader, get_one(db::table::kHeaderNumbers, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return kNumber; }
        ));
        EXPECT_CALL(db_reader, get_one(db::table::kHeaders, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return kHeader; }
        ));
        EXPECT_CALL(db_reader, get_one(db::table::kBlockBodies, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return kBody; }
        ));
        EXPECT_CALL(db_reader, walk(db::table::kEthTx, _, _, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<void> { co_return; }
        ));
        auto result = boost::asio::co_spawn(pool, read_block_by_number_or_hash(cache, db_reader, bnoh), boost::asio::use_future);
        const silkworm::BlockWithHash bwh = result.get();
        check_expected_block_with_hash(bwh);
    }

    SECTION("using tag kEarliestBlockId") {
        BlockNumberOrHash bnoh{kEarliestBlockId};
        BlockCache cache(10, true);

        EXPECT_CALL(db_reader, get_one(db::table::kCanonicalHashes, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return kBlockHash; }
        ));
        EXPECT_CALL(db_reader, get_one(db::table::kHeaders, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return kHeader; }
        ));
        EXPECT_CALL(db_reader, get_one(db::table::kBlockBodies, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return kBody; }
        ));
        EXPECT_CALL(db_reader, walk(db::table::kEthTx, _, _, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<void> { co_return; }
        ));
        auto result = boost::asio::co_spawn(pool, read_block_by_number_or_hash(cache, db_reader, bnoh), boost::asio::use_future);
        const silkworm::BlockWithHash bwh = result.get();
        check_expected_block_with_hash(bwh);
    }
}

TEST_CASE("silkrpc::core::read_block_by_number") {
    uint64_t bn = 5'000'001;
    boost::asio::thread_pool pool{1};
    MockDatabaseReader db_reader;
    BlockCache cache(10, true);

    SECTION("using valid block_number") {
        EXPECT_CALL(db_reader, get_one(db::table::kCanonicalHashes, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return kBlockHash; }
        ));
        EXPECT_CALL(db_reader, get_one(db::table::kHeaders, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return kHeader; }
        ));
        EXPECT_CALL(db_reader, get_one(db::table::kBlockBodies, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return kBody; }
        ));
        EXPECT_CALL(db_reader, walk(db::table::kEthTx, _, _, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<void> { co_return; }
        ));
        auto result = boost::asio::co_spawn(pool, silkrpc::core::read_block_by_number(cache, db_reader, bn), boost::asio::use_future);
        const silkworm::BlockWithHash bwh = result.get();
        check_expected_block_with_hash(bwh);
    }

    SECTION("using valid block_number and hit cache") {
        BlockCache cache(10, true);
        EXPECT_CALL(db_reader, get_one(db::table::kCanonicalHashes, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return kBlockHash; }
        ));
        EXPECT_CALL(db_reader, get_one(db::table::kHeaders, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return kHeader; }
        ));
        EXPECT_CALL(db_reader, get_one(db::table::kBlockBodies, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return kBody; }
        ));
        EXPECT_CALL(db_reader, walk(db::table::kEthTx, _, _, _)).WillOnce(Invoke(
            [](Unused, Unused, Unused, Walker w) -> boost::asio::awaitable<void> {
                silkworm::Bytes key{};
                silkworm::Bytes value{*silkworm::from_hex("f8ac8301942e8477359400834c4b40945f62669ba0c6cf41cc162d8157ed71a0b9d6dbaf80b844f2"
                    "f0387700000000000000000000000000000000000000000000000000000000000158b09f0270fc889c577c1c64db7c819f921d"
                    "1b6e8c7e5d3f2ff34f162cf4b324cc052ea0d5494ad16e2233197daa9d54cbbcb1ee534cf9f675fa587c264a4ce01e7d3d23a0"
                    "1421bcf57f4b39eb84a35042dc4675ae167f3e2f50e808252afa23e62e692355")};
                w(key, value);
                co_return;
            }
        ));
        EXPECT_CALL(db_reader, get_one(db::table::kSenders, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> {
                co_return *silkworm::from_hex("70A5C9D346416f901826581d423Cd5B92d44Ff5a");
            }
        ));
        auto result = boost::asio::co_spawn(pool, silkrpc::core::read_block_by_number(cache, db_reader, bn), boost::asio::use_future);
        const silkworm::BlockWithHash bwh = result.get();
        check_expected_block_with_hash(bwh);

        EXPECT_CALL(db_reader, get_one(db::table::kCanonicalHashes, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return kBlockHash; }
        ));
        auto result1 = boost::asio::co_spawn(pool, silkrpc::core::read_block_by_number(cache, db_reader, bn), boost::asio::use_future);
        const silkworm::BlockWithHash bwh1 = result1.get();
    }

    SECTION("using valid block_number and empty txs (miss cache)") {
        BlockCache cache(10, true);
        EXPECT_CALL(db_reader, get_one(db::table::kCanonicalHashes, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return kBlockHash; }
        ));
        EXPECT_CALL(db_reader, get_one(db::table::kHeaders, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return kHeader; }
        ));
        EXPECT_CALL(db_reader, get_one(db::table::kBlockBodies, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return kBody; }
        ));
        EXPECT_CALL(db_reader, walk(db::table::kEthTx, _, _, _)).WillOnce(Invoke(
            []() -> boost::asio::awaitable<void> { co_return; }
        ));
        auto result = boost::asio::co_spawn(pool, silkrpc::core::read_block_by_number(cache, db_reader, bn), boost::asio::use_future);
        const silkworm::BlockWithHash bwh = result.get();
        check_expected_block_with_hash(bwh);

        EXPECT_CALL(db_reader, get_one(db::table::kCanonicalHashes, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return kBlockHash; }
        ));
        EXPECT_CALL(db_reader, get_one(db::table::kHeaders, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return kHeader; }
        ));
        EXPECT_CALL(db_reader, get_one(db::table::kBlockBodies, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return kBody; }
        ));
        EXPECT_CALL(db_reader, walk(db::table::kEthTx, _, _, _)).WillOnce(Invoke(
            []() -> boost::asio::awaitable<void> { co_return; }
        ));
        auto result1 = boost::asio::co_spawn(pool, silkrpc::core::read_block_by_number(cache, db_reader, bn), boost::asio::use_future);
        const silkworm::BlockWithHash bwh1 = result1.get();
   }
}

TEST_CASE("silkrpc::core::read_block_by_hash") {
    const evmc::bytes32 bh = 0x439816753229fc0736bf86a5048de4bc9fcdede8c91dadf88c828c76b2281dff_bytes32;
    boost::asio::thread_pool pool{1};
    MockDatabaseReader db_reader;
    BlockCache cache(10, true);

    SECTION("using valid block_hash") {
        EXPECT_CALL(db_reader, get_one(db::table::kHeaderNumbers, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return kNumber; }
        ));
        EXPECT_CALL(db_reader, get_one(db::table::kHeaders, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return kHeader; }
        ));
        EXPECT_CALL(db_reader, get_one(db::table::kBlockBodies, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return kBody; }
        ));
        EXPECT_CALL(db_reader, walk(db::table::kEthTx, _, _, _)).WillOnce(Invoke(
            [](Unused, Unused, Unused, Walker w) -> boost::asio::awaitable<void> {
                silkworm::Bytes key{};
                silkworm::Bytes value{*silkworm::from_hex("f8ac8301942e8477359400834c4b40945f62669ba0c6cf41cc162d8157ed71a0b9d6dbaf80b844f2"
                    "f0387700000000000000000000000000000000000000000000000000000000000158b09f0270fc889c577c1c64db7c819f921d"
                    "1b6e8c7e5d3f2ff34f162cf4b324cc052ea0d5494ad16e2233197daa9d54cbbcb1ee534cf9f675fa587c264a4ce01e7d3d23a0"
                    "1421bcf57f4b39eb84a35042dc4675ae167f3e2f50e808252afa23e62e692355")};
                w(key, value);
                co_return;
            }
        ));
        EXPECT_CALL(db_reader, get_one(db::table::kSenders, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> {
                co_return *silkworm::from_hex("70A5C9D346416f901826581d423Cd5B92d44Ff5a");
            }
        ));
        auto result = boost::asio::co_spawn(pool, silkrpc::core::read_block_by_hash(cache, db_reader, bh), boost::asio::use_future);
        const silkworm::BlockWithHash bwh = result.get();
        check_expected_block_with_hash(bwh);
    }

    SECTION("using valid block_hash and hit cache") {
        EXPECT_CALL(db_reader, get_one(db::table::kHeaderNumbers, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return kNumber; }
        ));
        EXPECT_CALL(db_reader, get_one(db::table::kHeaders, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return kHeader; }
        ));
        EXPECT_CALL(db_reader, get_one(db::table::kBlockBodies, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return kBody; }
        ));
        EXPECT_CALL(db_reader, walk(db::table::kEthTx, _, _, _)).WillOnce(Invoke(
            [](Unused, Unused, Unused, Walker w) -> boost::asio::awaitable<void> {
                silkworm::Bytes key{};
                silkworm::Bytes value{*silkworm::from_hex("f8ac8301942e8477359400834c4b40945f62669ba0c6cf41cc162d8157ed71a0b9d6dbaf80b844f2"
                    "f0387700000000000000000000000000000000000000000000000000000000000158b09f0270fc889c577c1c64db7c819f921d"
                    "1b6e8c7e5d3f2ff34f162cf4b324cc052ea0d5494ad16e2233197daa9d54cbbcb1ee534cf9f675fa587c264a4ce01e7d3d23a0"
                    "1421bcf57f4b39eb84a35042dc4675ae167f3e2f50e808252afa23e62e692355")};
                w(key, value);
                co_return;
            }
        ));
        EXPECT_CALL(db_reader, get_one(db::table::kSenders, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> {
                co_return *silkworm::from_hex("70A5C9D346416f901826581d423Cd5B92d44Ff5a");
            }
        ));
        auto result = boost::asio::co_spawn(pool, silkrpc::core::read_block_by_hash(cache, db_reader, bh), boost::asio::use_future);
        const silkworm::BlockWithHash bwh = result.get();
        check_expected_block_with_hash(bwh);
        auto result1 = boost::asio::co_spawn(pool, silkrpc::core::read_block_by_hash(cache, db_reader, bh), boost::asio::use_future);
        const silkworm::BlockWithHash bwh1 = result1.get();
    }

    SECTION("using valid block_hash no txs (miss cache)") {
        EXPECT_CALL(db_reader, get_one(db::table::kHeaderNumbers, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return kNumber; }
        ));
        EXPECT_CALL(db_reader, get_one(db::table::kHeaders, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return kHeader; }
        ));
        EXPECT_CALL(db_reader, get_one(db::table::kBlockBodies, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return kBody; }
        ));
        EXPECT_CALL(db_reader, walk(db::table::kEthTx, _, _, _)).WillOnce(Invoke(
            []() -> boost::asio::awaitable<void> { co_return; }
        ));
        auto result = boost::asio::co_spawn(pool, silkrpc::core::read_block_by_hash(cache, db_reader, bh), boost::asio::use_future);
        const silkworm::BlockWithHash bwh = result.get();
        check_expected_block_with_hash(bwh);

        EXPECT_CALL(db_reader, get_one(db::table::kHeaderNumbers, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return kNumber; }
        ));
        EXPECT_CALL(db_reader, get_one(db::table::kHeaders, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return kHeader; }
        ));
        EXPECT_CALL(db_reader, get_one(db::table::kBlockBodies, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return kBody; }
        ));
        EXPECT_CALL(db_reader, walk(db::table::kEthTx, _, _, _)).WillOnce(Invoke(
            []() -> boost::asio::awaitable<void> { co_return; }
        ));
        auto result1 = boost::asio::co_spawn(pool, silkrpc::core::read_block_by_hash(cache, db_reader, bh), boost::asio::use_future);
        const silkworm::BlockWithHash bwh1 = result1.get();
    }
}

TEST_CASE("read_block_by_transaction_hash") {
    boost::asio::thread_pool pool{1};
    MockDatabaseReader db_reader;
    BlockCache cache(10, true);

    SECTION("block header number not found") {
        const auto transaction_hash{0x18dcb90e76b61fe6f37c9a9cd269a66188c05af5f7a62c50ff3246c6e207dc6d_bytes32};
        EXPECT_CALL(db_reader, get_one(db::table::kTxLookup, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return silkworm::Bytes{}; }
        ));
        auto result = boost::asio::co_spawn(pool, read_block_by_transaction_hash(cache, db_reader, transaction_hash), boost::asio::use_future);
        CHECK_THROWS_MATCHES(result.get(), std::invalid_argument, Message("empty block number value in read_block_by_transaction_hash"));
    }

    SECTION("invalid block header number") {
        const auto transaction_hash{0x18dcb90e76b61fe6f37c9a9cd269a66188c05af5f7a62c50ff3246c6e207dc6d_bytes32};
        EXPECT_CALL(db_reader, get_one(db::table::kTxLookup, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return *silkworm::from_hex("01FFFFFFFFFFFFFFFF"); }
        ));
        auto result = boost::asio::co_spawn(pool, read_block_by_transaction_hash(cache, db_reader, transaction_hash), boost::asio::use_future);
        CHECK_THROWS_AS(result.get(), std::out_of_range);
    }

    SECTION("block canonical hash not found") {
        const auto transaction_hash{0x18dcb90e76b61fe6f37c9a9cd269a66188c05af5f7a62c50ff3246c6e207dc6d_bytes32};
        EXPECT_CALL(db_reader, get_one(db::table::kTxLookup, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return *silkworm::from_hex("3D0900"); }
        ));
        EXPECT_CALL(db_reader, get_one(db::table::kCanonicalHashes, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return silkworm::Bytes{}; }
        ));
        auto result = boost::asio::co_spawn(pool, read_block_by_transaction_hash(cache, db_reader, transaction_hash), boost::asio::use_future);
        CHECK_THROWS_MATCHES(result.get(), std::invalid_argument, Message("empty block hash value in read_canonical_block_hash"));
    }

    SECTION("block header not found") {
        const auto transaction_hash{0x18dcb90e76b61fe6f37c9a9cd269a66188c05af5f7a62c50ff3246c6e207dc6d_bytes32};
        EXPECT_CALL(db_reader, get_one(db::table::kTxLookup, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return *silkworm::from_hex("3D0900"); }
        ));
        EXPECT_CALL(db_reader, get_one(db::table::kCanonicalHashes, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return kBlockHash; }
        ));
        EXPECT_CALL(db_reader, get_one(db::table::kHeaders, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return silkworm::Bytes{}; }
        ));
        auto result = boost::asio::co_spawn(pool, read_block_by_transaction_hash(cache, db_reader, transaction_hash), boost::asio::use_future);
        CHECK_THROWS_MATCHES(result.get(), std::runtime_error, Message("empty block header RLP in read_header"));
    }

    SECTION("block body not found") {
        const auto transaction_hash{0x18dcb90e76b61fe6f37c9a9cd269a66188c05af5f7a62c50ff3246c6e207dc6d_bytes32};
        EXPECT_CALL(db_reader, get_one(db::table::kTxLookup, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return *silkworm::from_hex("3D0900"); }
        ));
        EXPECT_CALL(db_reader, get_one(db::table::kCanonicalHashes, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return kBlockHash; }
        ));
        EXPECT_CALL(db_reader, get_one(db::table::kHeaders, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return kHeader; }
        ));
        EXPECT_CALL(db_reader, get_one(db::table::kBlockBodies, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return silkworm::Bytes{}; }
        ));
        auto result = boost::asio::co_spawn(pool, read_block_by_transaction_hash(cache, db_reader, transaction_hash), boost::asio::use_future);
        CHECK_THROWS_MATCHES(result.get(), std::runtime_error, Message("empty block body RLP in read_body"));
    }

    SECTION("block found and matching") {
        const auto transaction_hash{0x18dcb90e76b61fe6f37c9a9cd269a66188c05af5f7a62c50ff3246c6e207dc6d_bytes32};
        EXPECT_CALL(db_reader, get_one(db::table::kTxLookup, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return *silkworm::from_hex("3D0900"); }
        ));
        EXPECT_CALL(db_reader, get_one(db::table::kCanonicalHashes, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return kBlockHash; }
        ));
        EXPECT_CALL(db_reader, get_one(db::table::kHeaders, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return kHeader; }
        ));
        EXPECT_CALL(db_reader, get_one(db::table::kBlockBodies, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return kBody; }
        ));
        EXPECT_CALL(db_reader, walk(db::table::kEthTx, _, _, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<void> { co_return; }
        ));
        auto result = boost::asio::co_spawn(pool, read_block_by_transaction_hash(cache, db_reader, transaction_hash), boost::asio::use_future);
        const silkworm::BlockWithHash bwh = result.get();
        check_expected_block_with_hash(bwh);
    }
}

TEST_CASE("read_transaction_by_hash") {
    boost::asio::thread_pool pool{1};
    MockDatabaseReader db_reader;
    BlockCache cache(10, true);

    SECTION("block header number not found") {
        const auto transaction_hash{0x18dcb90e76b61fe6f37c9a9cd269a66188c05af5f7a62c50ff3246c6e207dc6d_bytes32};
        EXPECT_CALL(db_reader, get_one(db::table::kTxLookup, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return silkworm::Bytes{}; }
        ));
        auto result = boost::asio::co_spawn(pool, read_transaction_by_hash(cache, db_reader, transaction_hash), boost::asio::use_future);
        CHECK_THROWS_MATCHES(result.get(), std::invalid_argument, Message("empty block number value in read_block_by_transaction_hash"));
    }

    SECTION("invalid block header number") {
        const auto transaction_hash{0x18dcb90e76b61fe6f37c9a9cd269a66188c05af5f7a62c50ff3246c6e207dc6d_bytes32};
        EXPECT_CALL(db_reader, get_one(db::table::kTxLookup, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return *silkworm::from_hex("01FFFFFFFFFFFFFFFF"); }
        ));
        auto result = boost::asio::co_spawn(pool, read_transaction_by_hash(cache, db_reader, transaction_hash), boost::asio::use_future);
        CHECK_THROWS_AS(result.get(), std::out_of_range);
    }

    SECTION("transaction not found") {
        const auto transaction_hash{0x18dcb90e76b61fe6f37c9a9cd269a66188c05af5f7a62c50ff3246c6e207dc6d_bytes32};
        EXPECT_CALL(db_reader, get_one(db::table::kTxLookup, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return *silkworm::from_hex("3D0900"); }
        ));
        EXPECT_CALL(db_reader, get_one(db::table::kCanonicalHashes, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return kBlockHash; }
        ));
        EXPECT_CALL(db_reader, get_one(db::table::kHeaders, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return kHeader; }
        ));
        EXPECT_CALL(db_reader, get_one(db::table::kBlockBodies, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return kBody; }
        ));
        EXPECT_CALL(db_reader, walk(db::table::kEthTx, _, _, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<void> { co_return; }
        ));
        auto result = boost::asio::co_spawn(pool, read_transaction_by_hash(cache, db_reader, transaction_hash), boost::asio::use_future);
        CHECK(result.get() == std::nullopt);
    }

    SECTION("transaction found and matching") {
        const auto transaction_hash{0x3ff7b8917f1941784c709d6e54db18500fddc2b4c1a90b5cdec675cd0f9fc042_bytes32};
        EXPECT_CALL(db_reader, get_one(db::table::kTxLookup, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return *silkworm::from_hex("3D0900"); }
        ));
        EXPECT_CALL(db_reader, get_one(db::table::kCanonicalHashes, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return kBlockHash; }
        ));
        EXPECT_CALL(db_reader, get_one(db::table::kHeaders, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return kHeader; }
        ));
        EXPECT_CALL(db_reader, get_one(db::table::kBlockBodies, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> { co_return kNotEmptyBody; }
        ));
        EXPECT_CALL(db_reader, walk(db::table::kEthTx, _, _, _)).WillOnce(Invoke(
            [](Unused, Unused, Unused, Walker w) -> boost::asio::awaitable<void> {
                silkworm::Bytes key{};
                silkworm::Bytes value{*silkworm::from_hex("f8ac8301942e8477359400834c4b40945f62669ba0c6cf41cc162d8157ed71a0b9d6dbaf80b844f2"
                    "f0387700000000000000000000000000000000000000000000000000000000000158b09f0270fc889c577c1c64db7c819f921d"
                    "1b6e8c7e5d3f2ff34f162cf4b324cc052ea0d5494ad16e2233197daa9d54cbbcb1ee534cf9f675fa587c264a4ce01e7d3d23a0"
                    "1421bcf57f4b39eb84a35042dc4675ae167f3e2f50e808252afa23e62e692355")};
                w(key, value);
                co_return;
            }
        ));
        EXPECT_CALL(db_reader, get_one(db::table::kSenders, _)).WillOnce(InvokeWithoutArgs(
            []() -> boost::asio::awaitable<silkworm::Bytes> {
                co_return *silkworm::from_hex("70A5C9D346416f901826581d423Cd5B92d44Ff5a");
            }
        ));
        auto result = boost::asio::co_spawn(pool, read_transaction_by_hash(cache, db_reader, transaction_hash), boost::asio::use_future);
        const std::optional<silkrpc::TransactionWithBlock> block_and_transaction = result.get();
        CHECK(block_and_transaction.has_value());
        check_expected_transaction(block_and_transaction->transaction);
    }
}


} // namespace silkrpc::core::rawdb

