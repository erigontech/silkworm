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

#include "chain.hpp"

#include <string>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_exception.hpp>
#include <evmc/evmc.h>
#include <gmock/gmock.h>

#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/db/test_util/mock_transaction.hpp>
#include <silkworm/infra/test_util/context_test_base.hpp>

namespace silkworm::db::chain {

using Catch::Matchers::Message;
using testing::_;
using testing::InvokeWithoutArgs;
using testing::Unused;

static Bytes kNumber{*from_hex("00000000003D0900")};
static Bytes kBlockHash{*from_hex("439816753229fc0736bf86a5048de4bc9fcdede8c91dadf88c828c76b2281dff")};
static Bytes kHeader{*from_hex(
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
static Bytes kBody{*from_hex("c68369e45a03c0")};

struct ChainTest : public silkworm::test_util::ContextTestBase {
    test_util::MockTransaction transaction;
};

TEST_CASE_METHOD(ChainTest, "read_header_number") {
    SECTION("existent hash") {
        EXPECT_CALL(transaction, get_one(table::kHeaderNumbersName, _)).WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> { co_return kNumber; }));
        const evmc::bytes32 block_hash{0x439816753229fc0736bf86a5048de4bc9fcdede8c91dadf88c828c76b2281dff_bytes32};
        const auto header_number = spawn_and_wait(read_header_number(transaction, block_hash));
        CHECK(header_number == 4'000'000);
    }

    SECTION("non-existent hash") {
        EXPECT_CALL(transaction, get_one(table::kHeaderNumbersName, _)).WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
            co_return Bytes{};
        }));
        const evmc::bytes32 block_hash{0x0000000000000000000000000000000000000000000000000000000000000000_bytes32};
        auto result = spawn(read_header_number(transaction, block_hash));
#ifdef SILKWORM_SANITIZE  // Avoid comparison against exception message: it triggers a TSAN data race seemingly related to libstdc++ string implementation
        CHECK_THROWS_AS(result.get(), std::invalid_argument);
#else
        CHECK_THROWS_MATCHES(result.get(), std::invalid_argument, Message("empty block number value in read_header_number"));
#endif  // SILKWORM_SANITIZE
    }
}

TEST_CASE_METHOD(ChainTest, "read_total_difficulty") {
    SECTION("empty RLP buffer") {
        EXPECT_CALL(transaction, get_one(table::kDifficultyName, _)).WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
            co_return Bytes{};
        }));
        evmc::bytes32 block_hash{0xd268bdabee5eab4914d0de9b0e0071364582cfb3c952b19727f1ab429f4ba2a8_bytes32};
        const uint64_t block_number{4'000'000};
        CHECK_THROWS_AS(spawn_and_wait(read_total_difficulty(transaction, block_hash, block_number)), std::invalid_argument);
    }

    SECTION("invalid RLP buffer") {
        EXPECT_CALL(transaction, get_one(table::kDifficultyName, _)).WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
            co_return *from_hex("000102");
        }));
        evmc::bytes32 block_hash{0xd268bdabee5eab4914d0de9b0e0071364582cfb3c952b19727f1ab429f4ba2a8_bytes32};
        uint64_t block_number{4'000'000};
        CHECK_THROWS_AS(spawn_and_wait(read_total_difficulty(transaction, block_hash, block_number)), std::runtime_error);
    }

    SECTION("valid total difficulty") {
        EXPECT_CALL(transaction, get_one(table::kDifficultyName, _)).WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
            co_return *from_hex("8360c7cc");
        }));
        evmc::bytes32 block_hash{0xd268bdabee5eab4914d0de9b0e0071364582cfb3c952b19727f1ab429f4ba2a8_bytes32};
        uint64_t block_number{4'306'300};
        const auto total_difficulty = spawn_and_wait(read_total_difficulty(transaction, block_hash, block_number));
        CHECK(total_difficulty == 6'342'604 /*0x60c7cc*/);
    }
}

}  // namespace silkworm::db::chain
