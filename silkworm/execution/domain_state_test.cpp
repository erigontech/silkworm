/*
   Copyright 2025 The Silkworm Authors

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

#include "domain_state.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/use_future.hpp>
#include <catch2/catch_test_macros.hpp>
#include <evmc/evmc.hpp>
#include <gmock/gmock.h>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/db/test_util/mock_chain_storage.hpp>
#include <silkworm/db/test_util/mock_cursor.hpp>
#include <silkworm/db/test_util/mock_transaction.hpp>
#include <silkworm/db/test_util/mock_txn.hpp>
#include <silkworm/execution/database_tcontext.hpp>
#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/test_util/context_test_base.cpp>
#include <silkworm/infra/test_util/context_test_base.hpp>

namespace silkworm::execution {

using testing::_;
using testing::Invoke;
using testing::InvokeWithoutArgs;
using testing::Unused;

TEST_CASE("DomainState data access", "[execution][domain][state]") {
    TemporaryDirectory tmp_dir;
    TestDataStore ds_context{tmp_dir};

    auto rw_tx = ds_context.chaindata_rw().start_rw_tx();

    auto sut = DomainState{1, rw_tx, ds_context->chaindata(), ds_context->blocks_repository(), ds_context->state_repository()};
    auto header0_hash = sut.canonical_hash(0);
    auto header0 = sut.read_header(0, header0_hash.value());

    const silkworm::Hash header1_hash{0x7cb4dd3daba1f739d0c1ec7d998b4a2f6fd83019116455afa54ca4f49dfa0ad4_bytes32};

    SECTION("reads existing block") {
        auto header1 = sut.read_header(1, header1_hash);
        CHECK(header1.has_value());
        CHECK(header1->number == 1);
        CHECK(header1->hash() == header1_hash);
        CHECK(header1->parent_hash == header0_hash);
    }

    SECTION("reads non-existing block") {
        auto header2 = sut.read_header(2, header1_hash);
        CHECK_FALSE(header2.has_value());
    }

    SECTION("reads existing block body") {
        BlockBody body1{};
        auto body_read_ok = sut.read_body(1, header1_hash, body1);
        CHECK(body_read_ok);
        CHECK(body1.transactions.size() == 1);
    }

    SECTION("reads non-existing block body") {
        BlockBody body2{};
        auto body_read_ok = sut.read_body(2, header1_hash, body2);
        CHECK_FALSE(body_read_ok);
    }

    SECTION("reads existing total difficulty") {
        auto td1 = sut.total_difficulty(1, header1_hash);
        CHECK(td1.has_value());
        CHECK(*td1 == 17'171'480'576);
    }

    SECTION("reads head canonical block number") {
        auto head_block_num = sut.current_canonical_block();
        CHECK(head_block_num == 1);
    }

    //! Current genesis preloading does not store data to domain tables

    // SECTION("read_account preloaded block") {
    //     auto account_65 = sut.read_account(0x658bdf435d810c91414ec09147daa6db62406379_address);
    //     CHECK(account_65.has_value());
    //     CHECK(account_65->balance == intx::uint256{72, 8834426692912283648});
    // }

    // SECTION("read_code preloaded block") {
    //     auto code_aa = sut.read_code(
    //         0xaa00000000000000000000000000000000000000_address,
    //         0x39a32aa611e90196e88985d1de5179d967b0cab8d198f6186d5f4d3f073d4fbe_bytes32);
    //     CHECK(code_aa.size() > 0);
    //     CHECK(code_aa == from_hex("0x6042"));
    // }

    // SECTION("read_storage preloaded block") {
    //     auto storage_bb_01 = sut.read_storage(
    //         0xbb00000000000000000000000000000000000000_address,
    //         0,
    //         0x0100000000000000000000000000000000000000000000000000000000000000_bytes32);
    //     CHECK(storage_bb_01 == 0x0100000000000000000000000000000000000000000000000000000000000000_bytes32);
    // }

    SECTION("update_account") {
        Account account_66{
            .nonce = 123,
            .balance = 456,
            .incarnation = kDefaultIncarnation,
        };

        sut.update_account(
            0x668bdf435d810c91414ec09147daa6db62406379_address,
            account_66,
            {});

        auto account_66_read = sut.read_account(0x668bdf435d810c91414ec09147daa6db62406379_address);
        CHECK(account_66_read.has_value());
        CHECK(account_66_read->incarnation == kDefaultIncarnation);
        CHECK(account_66_read->nonce == 123);
        CHECK(account_66_read->balance == 456);
    }

    SECTION("update_account_code") {
        auto code_66 = *from_hex("0x6042");
        auto code_hash_66 = std::bit_cast<evmc_bytes32>(keccak256(code_66));

        sut.update_account_code(
            0x668bdf435d810c91414ec09147daa6db62406379_address,
            kDefaultIncarnation,
            code_hash_66,
            code_66);

        auto code_66_read = sut.read_code(0x668bdf435d810c91414ec09147daa6db62406379_address, code_hash_66);
        CHECK(code_66_read.size() > 0);
        CHECK(code_66_read == code_66);
    }

    SECTION("update_storage") {
        sut.update_storage(
            0x668bdf435d810c91414ec09147daa6db62406379_address,
            kDefaultIncarnation,
            0x010_bytes32,
            evmc::bytes32{},
            0x0123_bytes32);

        auto storage_66_01 = sut.read_storage(
            0x668bdf435d810c91414ec09147daa6db62406379_address,
            kDefaultIncarnation,
            0x010_bytes32);

        CHECK(storage_66_01 == 0x0123_bytes32);
    }
}

TEST_CASE("DomainState empty overriden methods do nothing", "[execution][domain][state]") {
    TemporaryDirectory tmp_dir;
    TestDataStore ds_context{tmp_dir};

    auto rw_tx = ds_context.chaindata_rw().start_rw_tx();

    auto sut = DomainState{1, rw_tx, ds_context->chaindata(), ds_context->blocks_repository(), ds_context->state_repository()};

    CHECK_NOTHROW(sut.insert_block(Block{}, evmc::bytes32{}));
    CHECK_NOTHROW(sut.canonize_block(0, evmc::bytes32{}));
    CHECK_NOTHROW(sut.decanonize_block(0));
    CHECK_NOTHROW(sut.insert_call_traces(0, CallTraces{}));
    CHECK_NOTHROW(sut.begin_block(0, 0));
    CHECK_NOTHROW(sut.unwind_state_changes(0));

    auto state_root_hash = sut.state_root_hash();
    CHECK(state_root_hash == evmc::bytes32{});
}
}  // namespace silkworm::execution
