/*
   Copyright 2023 The Silkworm Authors

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

#include "block_reader.hpp"

#include <string>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/use_future.hpp>
#include <catch2/catch_test_macros.hpp>
#include <gmock/gmock.h>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/db/test_util/mock_chain_storage.hpp>
#include <silkworm/db/test_util/mock_transaction.hpp>
#include <silkworm/rpc/common/worker_pool.hpp>
#include <silkworm/rpc/stagedsync/stages.hpp>

namespace silkworm::rpc::core {

using db::kv::api::KeyValue;
using db::test_util::MockChainStorage;
using db::test_util::MockTransaction;
using testing::_;
using testing::InvokeWithoutArgs;
namespace table = silkworm::db::table;

static silkworm::BlockNum kBlockNumber{0x3D0900};
static silkworm::Bytes kNumber{*silkworm::from_hex("00000000003D0900")};
static silkworm::Bytes block_hash = string_to_bytes(std::string("0x439816753229fc0736bf86a5048de4bc9fcdede8c91dadf88c828c76b2281dff"));
static silkworm::Bytes kHeader{*silkworm::from_hex(
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

static const silkworm::ByteView kExecutionStage{stages::kExecution};
// The following constants must stay here and outlive the spawned coroutine to avoid ASAN complains because:
// 1) passing const char* constants directly where const std::string& is expected creates references to temporary objects
// into the coroutine frame
// 2) when the coroutine is actually executed such references refer to destroyed stack objects, hence stack-use-after-scope error
static const std::string kEarliest = kEarliestBlockId;
static const std::string kLatest = kLatestBlockId;
static const std::string kLatestExecuted = kLatestExecutedBlockId;
static const std::string kPending = kPendingBlockId;
static const std::string kFinalized = kFinalizedBlockId;
static const std::string kSafe = kSafeBlockId;

TEST_CASE("get_block_num latest_required", "[rpc][core][blocks]") {
    MockTransaction transaction;
    MockChainStorage chain_storage;
    rpc::BlockReader block_reader{chain_storage, transaction};

    WorkerPool pool{1};

    SECTION("kEarliestBlockId") {
        auto result = boost::asio::co_spawn(pool, block_reader.get_block_num(kEarliest, /*latest_required=*/false), boost::asio::use_future);
        auto [block_num, ignore] = result.get();
        CHECK(block_num == kEarliestBlockNum);
    }

    SECTION("kLatestBlockId") {
        EXPECT_CALL(transaction, get(table::kLastForkchoiceName, _)).WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{silkworm::Bytes{}, silkworm::Bytes{}};
        }));

        EXPECT_CALL(transaction, get(table::kSyncStageProgressName, kExecutionStage)).WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{silkworm::Bytes{}, *silkworm::from_hex("1234567890123456")};
        }));
        auto result = boost::asio::co_spawn(pool, block_reader.get_block_num(kLatest, /*latest_required=*/false), boost::asio::use_future);
        auto [block_num, ignore] = result.get();
        CHECK(block_num == 0x1234567890123456);
    }

    SECTION("kLatestExecutedBlockId") {
        EXPECT_CALL(transaction, get(table::kSyncStageProgressName, kExecutionStage)).WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{silkworm::Bytes{}, *silkworm::from_hex("1234567890123456")};
        }));
        auto result = boost::asio::co_spawn(pool, block_reader.get_block_num(kLatestExecuted, /*latest_required=*/false), boost::asio::use_future);
        auto [block_num, ignore] = result.get();
        CHECK(block_num == 0x1234567890123456);
    }

    SECTION("kPendingBlockId") {
        EXPECT_CALL(transaction, get(table::kLastForkchoiceName, _)).WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{silkworm::Bytes{}, silkworm::Bytes{}};
        }));

        EXPECT_CALL(transaction, get(table::kSyncStageProgressName, kExecutionStage)).WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{silkworm::Bytes{}, *silkworm::from_hex("1234567890123456")};
        }));
        auto result = boost::asio::co_spawn(pool, block_reader.get_block_num(kPending, /*latest_required=*/false), boost::asio::use_future);
        auto [block_num, ignore] = result.get();
        CHECK(block_num == 0x1234567890123456);
    }

    SECTION("kFinalizedBlockId") {
        EXPECT_CALL(transaction, get(table::kLastForkchoiceName, _)).WillOnce(InvokeWithoutArgs([&]() -> Task<KeyValue> {
            co_return KeyValue{silkworm::Bytes{}, block_hash};
        }));
        EXPECT_CALL(chain_storage, read_block_num(_)).WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<BlockNum>> {
            co_return kBlockNumber;
        }));

        auto result = boost::asio::co_spawn(pool, block_reader.get_block_num(kFinalized, /*latest_required=*/false), boost::asio::use_future);
        auto [block_num, ignore] = result.get();
        CHECK(block_num == 0x3d0900);
    }

    SECTION("kSafeBlockId") {
        EXPECT_CALL(transaction, get(table::kLastForkchoiceName, _)).WillOnce(InvokeWithoutArgs([&]() -> Task<KeyValue> {
            co_return KeyValue{silkworm::Bytes{}, block_hash};
        }));
        EXPECT_CALL(chain_storage, read_block_num(_)).WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<BlockNum>> {
            co_return kBlockNumber;
        }));

        auto result = boost::asio::co_spawn(pool, block_reader.get_block_num(kSafe, /*latest_required=*/false), boost::asio::use_future);
        auto [block_num, ignore] = result.get();
        CHECK(block_num == 0x3d0900);
    }

    SECTION("block_num in hex") {
        static const std::string kBlockIdHex = "0x12345";
        auto result = boost::asio::co_spawn(pool, block_reader.get_block_num(kBlockIdHex, /*latest_required=*/false), boost::asio::use_future);
        auto [block_num, ignore] = result.get();
        CHECK(block_num == 0x12345);
    }

    SECTION("block_num in dec") {
        static const std::string kBlockIdDec = "67890";
        auto result = boost::asio::co_spawn(pool, block_reader.get_block_num(kBlockIdDec, /*latest_required=*/false), boost::asio::use_future);
        auto [block_num, ignore] = result.get();
        CHECK(block_num == 67890);
    }

    SECTION("block_num in hex & latest true") {
        static const std::string kBlockIdHex = "0x1234";
        EXPECT_CALL(transaction, get(table::kSyncStageProgressName, kExecutionStage)).WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{silkworm::Bytes{}, *silkworm::from_hex("0000000000001234")};
        }));
        auto result = boost::asio::co_spawn(pool, block_reader.get_block_num(kBlockIdHex, /*latest_required=*/true), boost::asio::use_future);
        auto [block_num, is_latest_block] = result.get();
        CHECK(block_num == 0x0000000000001234);
        CHECK(is_latest_block == true);
    }

    SECTION("block_num in hex & latest false") {
        static const std::string kBlockIdHex = "0x1234";
        EXPECT_CALL(transaction, get(table::kSyncStageProgressName, kExecutionStage)).WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{silkworm::Bytes{}, *silkworm::from_hex("0000000000001235")};
        }));
        auto result = boost::asio::co_spawn(pool, block_reader.get_block_num(kBlockIdHex, /*latest_required=*/true), boost::asio::use_future);
        auto [block_num, is_latest_block] = result.get();
        CHECK(block_num == 0x0000000000001234);
        CHECK(is_latest_block == false);
    }
}

TEST_CASE("get_block_num ", "[rpc][core][blocks]") {
    MockTransaction transaction;
    MockChainStorage chain_storage;
    rpc::BlockReader block_reader{chain_storage, transaction};
    WorkerPool pool{1};

    SECTION("kEarliestBlockId") {
        auto result = boost::asio::co_spawn(pool, block_reader.get_block_num(kEarliest), boost::asio::use_future);
        auto block_num = result.get();
        CHECK(block_num == kEarliestBlockNum);
    }
}

TEST_CASE("get_block_num_by_tag", "[rpc][core][blocks]") {
    MockTransaction transaction;
    MockChainStorage chain_storage;
    rpc::BlockReader block_reader{chain_storage, transaction};
    WorkerPool pool{1};

    SECTION("kEarliestBlockId") {
        auto result = boost::asio::co_spawn(pool, block_reader.get_block_num_by_tag(kEarliest), boost::asio::use_future);
        auto block_num = result.get();
        CHECK(block_num == kEarliestBlockNum);
    }

    SECTION("kLatestBlockId") {
        EXPECT_CALL(transaction, get(table::kLastForkchoiceName, _)).WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{silkworm::Bytes{}, silkworm::Bytes{}};
        }));

        EXPECT_CALL(transaction, get(table::kSyncStageProgressName, kExecutionStage)).WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{silkworm::Bytes{}, *silkworm::from_hex("1234567890123456")};
        }));
        auto result = boost::asio::co_spawn(pool, block_reader.get_block_num_by_tag(kLatest), boost::asio::use_future);
        auto block_num = result.get();
        CHECK(block_num == 0x1234567890123456);
    }

    SECTION("kLatestExecutedBlockId") {
        EXPECT_CALL(transaction, get(table::kSyncStageProgressName, kExecutionStage)).WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{silkworm::Bytes{}, *silkworm::from_hex("1234567890123456")};
        }));
        auto result = boost::asio::co_spawn(pool, block_reader.get_block_num_by_tag(kLatestExecuted), boost::asio::use_future);
        auto block_num = result.get();
        CHECK(block_num == 0x1234567890123456);
    }

    SECTION("kPendingBlockId") {
        EXPECT_CALL(transaction, get(table::kLastForkchoiceName, _)).WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{silkworm::Bytes{}, silkworm::Bytes{}};
        }));

        EXPECT_CALL(transaction, get(table::kSyncStageProgressName, kExecutionStage)).WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{silkworm::Bytes{}, *silkworm::from_hex("1234567890123456")};
        }));
        auto result = boost::asio::co_spawn(pool, block_reader.get_block_num_by_tag(kPending), boost::asio::use_future);
        auto block_num = result.get();
        CHECK(block_num == 0x1234567890123456);
    }

    SECTION("kFinalizedBlockId") {
        EXPECT_CALL(transaction, get(table::kLastForkchoiceName, _)).WillOnce(InvokeWithoutArgs([&]() -> Task<KeyValue> {
            co_return KeyValue{silkworm::Bytes{}, block_hash};
        }));

        EXPECT_CALL(chain_storage, read_block_num(_)).WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<BlockNum>> {
            co_return kBlockNumber;
        }));

        auto result = boost::asio::co_spawn(pool, block_reader.get_block_num_by_tag(kFinalized), boost::asio::use_future);
        auto block_num = result.get();
        CHECK(block_num == 0x3d0900);
    }

    SECTION("kSafeBlockId") {
        EXPECT_CALL(transaction, get(table::kLastForkchoiceName, _)).WillOnce(InvokeWithoutArgs([&]() -> Task<KeyValue> {
            co_return KeyValue{silkworm::Bytes{}, block_hash};
        }));
        EXPECT_CALL(chain_storage, read_block_num(_)).WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<BlockNum>> {
            co_return kBlockNumber;
        }));

        auto result = boost::asio::co_spawn(pool, block_reader.get_block_num_by_tag(kSafe), boost::asio::use_future);
        auto block_num = result.get();
        CHECK(block_num == 0x3d0900);
    }
}

TEST_CASE("get_current_block_num", "[rpc][core][blocks]") {
    static const silkworm::ByteView kFinishStage{stages::kFinish};
    MockTransaction transaction;
    MockChainStorage chain_storage;
    rpc::BlockReader block_reader{chain_storage, transaction};
    WorkerPool pool{1};

    EXPECT_CALL(transaction, get(table::kSyncStageProgressName, kFinishStage))
        .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{silkworm::Bytes{}, *silkworm::from_hex("0000ddff12121212")};
        }));
    auto result = boost::asio::co_spawn(pool, block_reader.get_current_block_num(), boost::asio::use_future);
    CHECK(result.get() == 0x0000ddff12121212);
}

TEST_CASE("get_max_block_num", "[rpc][core][blocks]") {
    static const silkworm::ByteView kHeadersStage{stages::kHeaders};
    MockTransaction transaction;
    MockChainStorage chain_storage;
    rpc::BlockReader block_reader{chain_storage, transaction};
    WorkerPool pool{1};

    EXPECT_CALL(transaction, get(table::kSyncStageProgressName, kHeadersStage))
        .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{silkworm::Bytes{}, *silkworm::from_hex("0000ddff12345678")};
        }));
    auto result = boost::asio::co_spawn(pool, block_reader.get_max_block_num(), boost::asio::use_future);
    CHECK(result.get() == 0x0000ddff12345678);
}

TEST_CASE("get_latest_block_num", "[rpc][core][blocks]") {
    MockTransaction transaction;
    MockChainStorage chain_storage;
    rpc::BlockReader block_reader{chain_storage, transaction};
    WorkerPool pool{1};

    EXPECT_CALL(transaction, get(table::kLastForkchoiceName, _)).WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
        co_return KeyValue{silkworm::Bytes{}, silkworm::Bytes{}};
    }));

    EXPECT_CALL(transaction, get(table::kSyncStageProgressName, kExecutionStage)).WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
        co_return KeyValue{silkworm::Bytes{}, *silkworm::from_hex("0000ddff12345678")};
    }));
    auto result = boost::asio::co_spawn(pool, block_reader.get_latest_block_num(), boost::asio::use_future);
    CHECK(result.get() == 0x0000ddff12345678);
}

TEST_CASE("get_latest_executed_block_num", "[rpc][core][blocks]") {
    MockTransaction transaction;
    MockChainStorage chain_storage;
    rpc::BlockReader block_reader{chain_storage, transaction};
    WorkerPool pool{1};

    EXPECT_CALL(transaction, get(table::kSyncStageProgressName, kExecutionStage)).WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
        co_return KeyValue{silkworm::Bytes{}, *silkworm::from_hex("0000ddff12345678")};
    }));
    auto result = boost::asio::co_spawn(pool, block_reader.get_latest_executed_block_num(), boost::asio::use_future);
    CHECK(result.get() == 0x0000ddff12345678);
}

TEST_CASE("get_latest_block_num with head forkchoice block_num", "[rpc][core][blocks]") {
    MockTransaction transaction;
    MockChainStorage chain_storage;
    rpc::BlockReader block_reader{chain_storage, transaction};
    WorkerPool pool{1};

    EXPECT_CALL(transaction, get(table::kLastForkchoiceName, _)).WillOnce(InvokeWithoutArgs([&]() -> Task<KeyValue> {
        co_return KeyValue{silkworm::Bytes{}, block_hash};
    }));
    EXPECT_CALL(chain_storage, read_block_num(_)).WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<BlockNum>> {
        co_return kBlockNumber;
    }));

    auto result = boost::asio::co_spawn(pool, block_reader.get_latest_block_num(), boost::asio::use_future);
    CHECK(result.get() == 0x3d0900);
}

TEST_CASE("get_forkchoice_finalized_block_num genesis block_num if no finalized block", "[rpc][core][blocks]") {
    MockTransaction transaction;
    MockChainStorage chain_storage;
    rpc::BlockReader block_reader{chain_storage, transaction};
    WorkerPool pool{1};

    EXPECT_CALL(transaction, get(table::kLastForkchoiceName, _)).WillOnce(InvokeWithoutArgs([&]() -> Task<KeyValue> {
        co_return KeyValue{silkworm::Bytes{}, silkworm::Bytes{}};
    }));

    auto result = boost::asio::co_spawn(pool, block_reader.get_forkchoice_finalized_block_num(), boost::asio::use_future);
    CHECK(result.get() == 0x0);
}

TEST_CASE("get_forkchoice_safe_block_num genesis block_num if no safe block", "[rpc][core][blocks]") {
    MockTransaction transaction;
    MockChainStorage chain_storage;
    rpc::BlockReader block_reader{chain_storage, transaction};
    WorkerPool pool{1};

    EXPECT_CALL(transaction, get(table::kLastForkchoiceName, _)).WillOnce(InvokeWithoutArgs([&]() -> Task<KeyValue> {
        co_return KeyValue{silkworm::Bytes{}, silkworm::Bytes{}};
    }));

    auto result = boost::asio::co_spawn(pool, block_reader.get_forkchoice_safe_block_num(), boost::asio::use_future);
    CHECK(result.get() == 0x0);
}

TEST_CASE("is_latest_block_num", "[rpc][core][blocks]") {
    MockTransaction transaction;
    MockChainStorage chain_storage;
    rpc::BlockReader block_reader{chain_storage, transaction};
    WorkerPool pool{1};

    SECTION("tag: latest") {
        BlockNumOrHash block_num_or_hash{"latest"};
        auto result = boost::asio::co_spawn(pool, block_reader.is_latest_block_num(block_num_or_hash), boost::asio::use_future);
        CHECK(result.get());
    }

    SECTION("tag: pending") {
        BlockNumOrHash block_num_or_hash{"pending"};
        auto result = boost::asio::co_spawn(pool, block_reader.is_latest_block_num(block_num_or_hash), boost::asio::use_future);
        CHECK(result.get());
    }

    SECTION("block_num: latest") {
        BlockNumOrHash block_num_or_hash{1'000'000};
        // Mock reader shall be used to read the latest block from Execution stage in table SyncStageProgress
        EXPECT_CALL(transaction, get(table::kLastForkchoiceName, _)).WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{silkworm::Bytes{}, silkworm::Bytes{}};
        }));

        EXPECT_CALL(transaction, get(table::kSyncStageProgressName, kExecutionStage))
            .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{silkworm::Bytes{}, *silkworm::from_hex("00000000000F4240")};
            }));
        auto result = boost::asio::co_spawn(pool, block_reader.is_latest_block_num(block_num_or_hash), boost::asio::use_future);
        CHECK(result.get());
    }

    SECTION("block_num: not latest") {
        BlockNumOrHash block_num_or_hash{1'000'000};
        // Mock reader shall be used to read the latest block from Execution stage in table SyncStageProgress
        EXPECT_CALL(transaction, get(table::kLastForkchoiceName, _)).WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{silkworm::Bytes{}, silkworm::Bytes{}};
        }));

        EXPECT_CALL(transaction, get(table::kSyncStageProgressName, kExecutionStage))
            .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{silkworm::Bytes{}, *silkworm::from_hex("00000000000F4241")};
            }));
        auto result = boost::asio::co_spawn(pool, block_reader.is_latest_block_num(block_num_or_hash), boost::asio::use_future);
        CHECK(!result.get());
    }
}

}  // namespace silkworm::rpc::core
