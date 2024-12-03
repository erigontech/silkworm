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

#include "blocks.hpp"

#include <string>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/use_future.hpp>
#include <catch2/catch_test_macros.hpp>
#include <gmock/gmock.h>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/db/test_util/mock_transaction.hpp>
#include <silkworm/rpc/common/worker_pool.hpp>
#include <silkworm/rpc/stagedsync/stages.hpp>

namespace silkworm::rpc::core {

using db::kv::api::KeyValue;
using db::test_util::MockTransaction;
using testing::_;
using testing::InvokeWithoutArgs;
namespace table = silkworm::db::table;

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

TEST_CASE("get_block_num latest_required", "[rpc][core][blocks]") {
    // SILK_LOG_STREAMS(test_util::null_stream(), test_util::null_stream());
    const silkworm::ByteView execution_stage{stages::kExecution};
    MockTransaction transaction;
    WorkerPool pool{1};

    SECTION("kEarliestBlockId") {
        const std::string earliest_block_id = kEarliestBlockId;
        auto result = boost::asio::co_spawn(pool, get_block_num(earliest_block_id, transaction, /*latest_required=*/false), boost::asio::use_future);
        auto [block_num, ignore] = result.get();
        CHECK(block_num == kEarliestBlockNum);
    }

    SECTION("kLatestBlockId") {
        const std::string latest_block_id = kLatestBlockId;
        EXPECT_CALL(transaction, get(table::kLastForkchoiceName, _)).WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{silkworm::Bytes{}, silkworm::Bytes{}};
        }));

        EXPECT_CALL(transaction, get(table::kSyncStageProgressName, execution_stage)).WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{silkworm::Bytes{}, *silkworm::from_hex("1234567890123456")};
        }));
        auto result = boost::asio::co_spawn(pool, get_block_num(latest_block_id, transaction, /*latest_required=*/false), boost::asio::use_future);
        auto [block_num, ignore] = result.get();
        CHECK(block_num == 0x1234567890123456);
    }

    SECTION("kLatestExecutedBlockId") {
        const std::string latest_block_id = kLatestExecutedBlockId;
        EXPECT_CALL(transaction, get(table::kSyncStageProgressName, execution_stage)).WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{silkworm::Bytes{}, *silkworm::from_hex("1234567890123456")};
        }));
        auto result = boost::asio::co_spawn(pool, get_block_num(latest_block_id, transaction, /*latest_required=*/false), boost::asio::use_future);
        auto [block_num, ignore] = result.get();
        CHECK(block_num == 0x1234567890123456);
    }

    SECTION("kPendingBlockId") {
        const std::string pending_block_id = kPendingBlockId;
        EXPECT_CALL(transaction, get(table::kLastForkchoiceName, _)).WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{silkworm::Bytes{}, silkworm::Bytes{}};
        }));

        EXPECT_CALL(transaction, get(table::kSyncStageProgressName, execution_stage)).WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{silkworm::Bytes{}, *silkworm::from_hex("1234567890123456")};
        }));
        auto result = boost::asio::co_spawn(pool, get_block_num(pending_block_id, transaction, /*latest_required=*/false), boost::asio::use_future);
        auto [block_num, ignore] = result.get();
        CHECK(block_num == 0x1234567890123456);
    }

    SECTION("kFinalizedBlockId") {
        const std::string finalized_forkchoice_block_id = kFinalizedBlockId;
        EXPECT_CALL(transaction, get(table::kLastForkchoiceName, _)).WillOnce(InvokeWithoutArgs([&]() -> Task<KeyValue> {
            co_return KeyValue{silkworm::Bytes{}, block_hash};
        }));

        EXPECT_CALL(transaction, get_one(table::kHeaderNumbersName, _)).WillOnce(InvokeWithoutArgs([]() -> Task<silkworm::Bytes> {
            co_return kNumber;
        }));

        auto result = boost::asio::co_spawn(pool, get_block_num(finalized_forkchoice_block_id, transaction, /*latest_required=*/false), boost::asio::use_future);
        auto [block_num, ignore] = result.get();
        CHECK(block_num == 0x3d0900);
    }

    SECTION("kSafeBlockId") {
        const std::string safe_forkchoice_block_id = kSafeBlockId;
        EXPECT_CALL(transaction, get(table::kLastForkchoiceName, _)).WillOnce(InvokeWithoutArgs([&]() -> Task<KeyValue> {
            co_return KeyValue{silkworm::Bytes{}, block_hash};
        }));

        EXPECT_CALL(transaction, get_one(table::kHeaderNumbersName, _)).WillOnce(InvokeWithoutArgs([]() -> Task<silkworm::Bytes> {
            co_return kNumber;
        }));

        auto result = boost::asio::co_spawn(pool, get_block_num(safe_forkchoice_block_id, transaction, /*latest_required=*/false), boost::asio::use_future);
        auto [block_num, ignore] = result.get();
        CHECK(block_num == 0x3d0900);
    }

    SECTION("block_num in hex") {
        const std::string block_id_hex = "0x12345";
        auto result = boost::asio::co_spawn(pool, get_block_num(block_id_hex, transaction, /*latest_required=*/false), boost::asio::use_future);
        auto [block_num, ignore] = result.get();
        CHECK(block_num == 0x12345);
    }

    SECTION("block_num in dec") {
        const std::string block_id_dec = "67890";
        auto result = boost::asio::co_spawn(pool, get_block_num(block_id_dec, transaction, /*latest_required=*/false), boost::asio::use_future);
        REQUIRE_THROWS(result.get());
    }

    SECTION("block_num in hex & latest true") {
        const std::string block_id_hex = "0x1234";
        EXPECT_CALL(transaction, get(table::kSyncStageProgressName, execution_stage)).WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{silkworm::Bytes{}, *silkworm::from_hex("0000000000001234")};
        }));
        auto result = boost::asio::co_spawn(pool, get_block_num(block_id_hex, transaction, /*latest_required=*/true), boost::asio::use_future);
        auto [block_num, is_latest_block] = result.get();
        CHECK(block_num == 0x0000000000001234);
        CHECK(is_latest_block == true);
    }

    SECTION("block_num in hex & latest false") {
        const std::string block_id_hex = "0x1234";
        EXPECT_CALL(transaction, get(table::kSyncStageProgressName, execution_stage)).WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{silkworm::Bytes{}, *silkworm::from_hex("0000000000001235")};
        }));
        auto result = boost::asio::co_spawn(pool, get_block_num(block_id_hex, transaction, /*latest_required=*/true), boost::asio::use_future);
        auto [block_num, is_latest_block] = result.get();
        CHECK(block_num == 0x0000000000001234);
        CHECK(is_latest_block == false);
    }
}

TEST_CASE("get_block_num ", "[rpc][core][blocks]") {
    // SILK_LOG_STREAMS(null_stream(), null_stream());
    MockTransaction transaction;
    WorkerPool pool{1};

    SECTION("kEarliestBlockId") {
        const std::string earliest_block_id = kEarliestBlockId;
        auto result = boost::asio::co_spawn(pool, get_block_num(earliest_block_id, transaction), boost::asio::use_future);
        auto block_num = result.get();
        CHECK(block_num == kEarliestBlockNum);
    }
}

TEST_CASE("get_block_num_by_tag", "[rpc][core][blocks]") {
    // SILK_LOG_STREAMS(null_stream(), null_stream());
    const silkworm::ByteView execution_stage{stages::kExecution};
    MockTransaction transaction;
    WorkerPool pool{1};

    SECTION("kEarliestBlockId") {
        const std::string earliest_block_id = kEarliestBlockId;
        auto result = boost::asio::co_spawn(pool, get_block_num_by_tag(earliest_block_id, transaction), boost::asio::use_future);
        auto block_num = result.get();
        CHECK(block_num == kEarliestBlockNum);
    }

    SECTION("kLatestBlockId") {
        const std::string latest_block_id = kLatestBlockId;
        EXPECT_CALL(transaction, get(table::kLastForkchoiceName, _)).WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{silkworm::Bytes{}, silkworm::Bytes{}};
        }));

        EXPECT_CALL(transaction, get(table::kSyncStageProgressName, execution_stage)).WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{silkworm::Bytes{}, *silkworm::from_hex("1234567890123456")};
        }));
        auto result = boost::asio::co_spawn(pool, get_block_num_by_tag(latest_block_id, transaction), boost::asio::use_future);
        auto block_num = result.get();
        CHECK(block_num == 0x1234567890123456);
    }

    SECTION("kLatestExecutedBlockId") {
        const std::string latest_block_id = kLatestExecutedBlockId;
        EXPECT_CALL(transaction, get(table::kSyncStageProgressName, execution_stage)).WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{silkworm::Bytes{}, *silkworm::from_hex("1234567890123456")};
        }));
        auto result = boost::asio::co_spawn(pool, get_block_num_by_tag(latest_block_id, transaction), boost::asio::use_future);
        auto block_num = result.get();
        CHECK(block_num == 0x1234567890123456);
    }

    SECTION("kPendingBlockId") {
        const std::string pending_block_id = kPendingBlockId;
        EXPECT_CALL(transaction, get(table::kLastForkchoiceName, _)).WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{silkworm::Bytes{}, silkworm::Bytes{}};
        }));

        EXPECT_CALL(transaction, get(table::kSyncStageProgressName, execution_stage)).WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{silkworm::Bytes{}, *silkworm::from_hex("1234567890123456")};
        }));
        auto result = boost::asio::co_spawn(pool, get_block_num_by_tag(pending_block_id, transaction), boost::asio::use_future);
        auto block_num = result.get();
        CHECK(block_num == 0x1234567890123456);
    }

    SECTION("kFinalizedBlockId") {
        const std::string finalized_forkchoice_block_id = kFinalizedBlockId;
        EXPECT_CALL(transaction, get(table::kLastForkchoiceName, _)).WillOnce(InvokeWithoutArgs([&]() -> Task<KeyValue> {
            co_return KeyValue{silkworm::Bytes{}, block_hash};
        }));

        EXPECT_CALL(transaction, get_one(table::kHeaderNumbersName, _)).WillOnce(InvokeWithoutArgs([]() -> Task<silkworm::Bytes> {
            co_return kNumber;
        }));

        auto result = boost::asio::co_spawn(pool, get_block_num_by_tag(finalized_forkchoice_block_id, transaction), boost::asio::use_future);
        auto block_num = result.get();
        CHECK(block_num == 0x3d0900);
    }

    SECTION("kSafeBlockId") {
        const std::string safe_forkchoice_block_id = kSafeBlockId;
        EXPECT_CALL(transaction, get(table::kLastForkchoiceName, _)).WillOnce(InvokeWithoutArgs([&]() -> Task<KeyValue> {
            co_return KeyValue{silkworm::Bytes{}, block_hash};
        }));

        EXPECT_CALL(transaction, get_one(table::kHeaderNumbersName, _)).WillOnce(InvokeWithoutArgs([]() -> Task<silkworm::Bytes> {
            co_return kNumber;
        }));

        auto result = boost::asio::co_spawn(pool, get_block_num_by_tag(safe_forkchoice_block_id, transaction), boost::asio::use_future);
        auto block_num = result.get();
        CHECK(block_num == 0x3d0900);
    }
}

TEST_CASE("get_current_block_num", "[rpc][core][blocks]") {
    const silkworm::ByteView finish_stage{stages::kFinish};
    MockTransaction transaction;
    WorkerPool pool{1};

    EXPECT_CALL(transaction, get(table::kSyncStageProgressName, finish_stage))
        .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{silkworm::Bytes{}, *silkworm::from_hex("0000ddff12121212")};
        }));
    auto result = boost::asio::co_spawn(pool, get_current_block_num(transaction), boost::asio::use_future);
    CHECK(result.get() == 0x0000ddff12121212);
}

TEST_CASE("get_max_block_num", "[rpc][core][blocks]") {
    const silkworm::ByteView headers_stage{stages::kHeaders};
    MockTransaction transaction;
    WorkerPool pool{1};

    EXPECT_CALL(transaction, get(table::kSyncStageProgressName, headers_stage))
        .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{silkworm::Bytes{}, *silkworm::from_hex("0000ddff12345678")};
        }));
    auto result = boost::asio::co_spawn(pool, get_max_block_num(transaction), boost::asio::use_future);
    CHECK(result.get() == 0x0000ddff12345678);
}

TEST_CASE("get_latest_block_num", "[rpc][core][blocks]") {
    const silkworm::ByteView execution_stage{stages::kExecution};
    MockTransaction transaction;
    WorkerPool pool{1};

    EXPECT_CALL(transaction, get(table::kLastForkchoiceName, _)).WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
        co_return KeyValue{silkworm::Bytes{}, silkworm::Bytes{}};
    }));

    EXPECT_CALL(transaction, get(table::kSyncStageProgressName, execution_stage)).WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
        co_return KeyValue{silkworm::Bytes{}, *silkworm::from_hex("0000ddff12345678")};
    }));
    auto result = boost::asio::co_spawn(pool, get_latest_block_num(transaction), boost::asio::use_future);
    CHECK(result.get() == 0x0000ddff12345678);
}

TEST_CASE("get_latest_executed_block_num", "[rpc][core][blocks]") {
    const silkworm::ByteView execution_stage{stages::kExecution};
    MockTransaction transaction;
    WorkerPool pool{1};

    EXPECT_CALL(transaction, get(table::kSyncStageProgressName, execution_stage)).WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
        co_return KeyValue{silkworm::Bytes{}, *silkworm::from_hex("0000ddff12345678")};
    }));
    auto result = boost::asio::co_spawn(pool, get_latest_executed_block_num(transaction), boost::asio::use_future);
    CHECK(result.get() == 0x0000ddff12345678);
}

TEST_CASE("get_latest_block_num with head forkchoice block_num", "[rpc][core][blocks]") {
    MockTransaction transaction;
    WorkerPool pool{1};

    EXPECT_CALL(transaction, get(table::kLastForkchoiceName, _)).WillOnce(InvokeWithoutArgs([&]() -> Task<KeyValue> {
        co_return KeyValue{silkworm::Bytes{}, block_hash};
    }));

    EXPECT_CALL(transaction, get_one(table::kHeaderNumbersName, _)).WillOnce(InvokeWithoutArgs([]() -> Task<silkworm::Bytes> {
        co_return kNumber;
    }));

    auto result = boost::asio::co_spawn(pool, get_latest_block_num(transaction), boost::asio::use_future);
    CHECK(result.get() == 0x3d0900);
}

TEST_CASE("get_forkchoice_finalized_block_num genesis block_num if no finalized block", "[rpc][core][blocks]") {
    MockTransaction transaction;
    WorkerPool pool{1};

    EXPECT_CALL(transaction, get(table::kLastForkchoiceName, _)).WillOnce(InvokeWithoutArgs([&]() -> Task<KeyValue> {
        co_return KeyValue{silkworm::Bytes{}, silkworm::Bytes{}};
    }));

    auto result = boost::asio::co_spawn(pool, get_forkchoice_finalized_block_num(transaction), boost::asio::use_future);
    CHECK(result.get() == 0x0);
}

TEST_CASE("get_forkchoice_safe_block_num genesis block_num if no safe block", "[rpc][core][blocks]") {
    MockTransaction transaction;
    WorkerPool pool{1};

    EXPECT_CALL(transaction, get(table::kLastForkchoiceName, _)).WillOnce(InvokeWithoutArgs([&]() -> Task<KeyValue> {
        co_return KeyValue{silkworm::Bytes{}, silkworm::Bytes{}};
    }));

    auto result = boost::asio::co_spawn(pool, get_forkchoice_safe_block_num(transaction), boost::asio::use_future);
    CHECK(result.get() == 0x0);
}

TEST_CASE("is_latest_block_num", "[rpc][core][blocks]") {
    const silkworm::ByteView execution_stage{stages::kExecution};
    MockTransaction transaction;
    WorkerPool pool{1};

    SECTION("tag: latest") {
        BlockNumOrHash block_num_or_hash{"latest"};
        auto result = boost::asio::co_spawn(pool, is_latest_block_num(block_num_or_hash, transaction), boost::asio::use_future);
        CHECK(result.get());
    }

    SECTION("tag: pending") {
        BlockNumOrHash block_num_or_hash{"pending"};
        auto result = boost::asio::co_spawn(pool, is_latest_block_num(block_num_or_hash, transaction), boost::asio::use_future);
        CHECK(result.get());
    }

    SECTION("block_num: latest") {
        BlockNumOrHash block_num_or_hash{1'000'000};
        // Mock reader shall be used to read the latest block from Execution stage in table SyncStageProgress
        EXPECT_CALL(transaction, get(table::kLastForkchoiceName, _)).WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{silkworm::Bytes{}, silkworm::Bytes{}};
        }));

        EXPECT_CALL(transaction, get(table::kSyncStageProgressName, execution_stage))
            .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{silkworm::Bytes{}, *silkworm::from_hex("00000000000F4240")};
            }));
        auto result = boost::asio::co_spawn(pool, is_latest_block_num(block_num_or_hash, transaction), boost::asio::use_future);
        CHECK(result.get());
    }

    SECTION("block_num: not latest") {
        BlockNumOrHash block_num_or_hash{1'000'000};
        // Mock reader shall be used to read the latest block from Execution stage in table SyncStageProgress
        EXPECT_CALL(transaction, get(table::kLastForkchoiceName, _)).WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{silkworm::Bytes{}, silkworm::Bytes{}};
        }));

        EXPECT_CALL(transaction, get(table::kSyncStageProgressName, execution_stage))
            .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{silkworm::Bytes{}, *silkworm::from_hex("00000000000F4241")};
            }));
        auto result = boost::asio::co_spawn(pool, is_latest_block_num(block_num_or_hash, transaction), boost::asio::use_future);
        CHECK(!result.get());
    }
}

}  // namespace silkworm::rpc::core
