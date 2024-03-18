/*
   Copyright 2024 The Silkworm Authors

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

#include "silkworm.h"

#include <cstring>
#include <iostream>

#include <catch2/catch.hpp>

#include <silkworm/core/trie/vector_root.hpp>
#include <silkworm/db/mdbx/mdbx.hpp>
#include <silkworm/db/snapshots/index.hpp>
#include <silkworm/db/snapshots/snapshot.hpp>
#include <silkworm/db/snapshots/test_util/common.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/rpc/test/api_test_database.hpp>

namespace silkworm {

namespace snapshot_test = snapshots::test_util;

struct CApiTest : public rpc::test::TestDatabaseContext {
  private:
    // TODO(canepat) remove test_util::StreamSwap objects when C API settings include log level
    std::stringstream string_cout, string_cerr;
    test_util::StreamSwap cout_swap{std::cout, string_cout};
    test_util::StreamSwap cerr_swap{std::cerr, string_cerr};

    test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};
};

//! Utility to copy `src` C-string to `dst` fixed-size char array
template <size_t N>
static void c_string_copy(char dst[N], const char* src) {
    std::strncpy(dst, src, N - 1);
    dst[N - 1] = '\0';
}

//! Utility to copy `src` C-string in 'git describe' format to `dst`
static void copy_git_version(char dst[SILKWORM_GIT_VERSION_SIZE], const char* src) {
    c_string_copy<SILKWORM_GIT_VERSION_SIZE>(dst, src);
}

//! Utility to copy `src` C-string fixed-size path to `dst`
static void copy_path(char dst[SILKWORM_PATH_SIZE], const char* src) {
    c_string_copy<SILKWORM_PATH_SIZE>(dst, src);
}

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_libmdbx_version: OK", "[silkworm][capi]") {
    CHECK(std::strcmp(silkworm_libmdbx_version(), ::mdbx::get_version().git.describe) == 0);
}

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_init: empty settings", "[silkworm][capi]") {
    SilkwormSettings settings{};
    SilkwormHandle handle{nullptr};
    CHECK(silkworm_init(&handle, &settings) == SILKWORM_INVALID_PATH);
    CHECK(!handle);
}

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_init: empty data folder path", "[silkworm][capi]") {
    SilkwormSettings settings{};
    copy_path(settings.data_dir_path, "");
    copy_git_version(settings.libmdbx_version, silkworm_libmdbx_version());
    SilkwormHandle handle{nullptr};
    CHECK(silkworm_init(&handle, &settings) == SILKWORM_INVALID_PATH);
    CHECK(!handle);
}

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_init: empty MDBX version", "[silkworm][capi]") {
    SilkwormSettings settings{};
    copy_path(settings.data_dir_path, db.get_path().string().c_str());
    copy_git_version(settings.libmdbx_version, "");
    SilkwormHandle handle{nullptr};
    CHECK(silkworm_init(&handle, &settings) == SILKWORM_INCOMPATIBLE_LIBMDBX);
    CHECK(!handle);
}

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_init: incompatible MDBX version", "[silkworm][capi]") {
    SilkwormSettings settings{};
    copy_path(settings.data_dir_path, db.get_path().string().c_str());
    copy_git_version(settings.libmdbx_version, "v0.1.0");
    SilkwormHandle handle{nullptr};
    CHECK(silkworm_init(&handle, &settings) == SILKWORM_INCOMPATIBLE_LIBMDBX);
    CHECK(!handle);
}

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_init: OK", "[silkworm][capi]") {
    SilkwormSettings settings{};
    copy_path(settings.data_dir_path, db.get_path().string().c_str());
    copy_git_version(settings.libmdbx_version, silkworm_libmdbx_version());
    SilkwormHandle handle{nullptr};
    CHECK(silkworm_init(&handle, &settings) == SILKWORM_OK);
    CHECK(handle);
    CHECK(silkworm_fini(handle) == SILKWORM_OK);
}

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_fini: not initialized", "[silkworm][capi]") {
    SilkwormHandle handle{nullptr};
    CHECK(silkworm_fini(handle) == SILKWORM_INVALID_HANDLE);
}

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_fini: OK", "[silkworm][capi]") {
    SilkwormSettings settings{};
    copy_path(settings.data_dir_path, db.get_path().string().c_str());
    copy_git_version(settings.libmdbx_version, silkworm_libmdbx_version());
    SilkwormHandle handle{nullptr};
    REQUIRE(silkworm_init(&handle, &settings) == SILKWORM_OK);
    CHECK(silkworm_fini(handle) == SILKWORM_OK);
}

//! \brief Utility class using RAII pattern to wrap the Silkworm C API.
//! \note This is useful for tests that do *not* specifically play with silkworm_init/silkworm_fini or invalid handles
struct SilkwormLibrary {
    explicit SilkwormLibrary(const std::filesystem::path& db_path) {
        SilkwormSettings settings{};
        copy_path(settings.data_dir_path, db_path.string().c_str());
        copy_git_version(settings.libmdbx_version, silkworm_libmdbx_version());
        silkworm_init(&handle_, &settings);
    }
    ~SilkwormLibrary() {
        silkworm_fini(handle_);
    }

    struct ExecutionResult {
        int execute_block_result{0};
        BlockNum last_executed_block{0};
        int mdbx_error_code{0};
    };

    ExecutionResult execute_blocks(MDBX_txn* txn,
                                   uint64_t chain_id,
                                   uint64_t start_block,
                                   uint64_t max_block,
                                   uint64_t batch_size,
                                   bool write_change_sets,
                                   bool write_receipts,
                                   bool write_call_traces) {
        ExecutionResult result;
        result.execute_block_result =
            silkworm_execute_blocks_ephemeral(handle_, txn,
                                              chain_id, start_block, max_block, batch_size,
                                              write_change_sets, write_receipts, write_call_traces,
                                              &result.last_executed_block, &result.mdbx_error_code);
        return result;
    }

    ExecutionResult execute_blocks_perpetual(MDBX_env* env,
                                             uint64_t chain_id,
                                             uint64_t start_block,
                                             uint64_t max_block,
                                             uint64_t batch_size,
                                             bool write_change_sets,
                                             bool write_receipts,
                                             bool write_call_traces) {
        ExecutionResult result;
        result.execute_block_result =
            silkworm_execute_blocks_perpetual(handle_, env,
                                              chain_id, start_block, max_block, batch_size,
                                              write_change_sets, write_receipts, write_call_traces,
                                              &result.last_executed_block, &result.mdbx_error_code);
        return result;
    }

    int add_snapshot(SilkwormChainSnapshot* snapshot) {
        return silkworm_add_snapshot(handle_, snapshot);
    }

  private:
    SilkwormHandle handle_{nullptr};
};

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_execute_blocks_ephemeral: block not found", "[silkworm][capi]") {
    // Use Silkworm as a library with silkworm_init/silkworm_fini automated by RAII
    SilkwormLibrary silkworm_lib{db.get_path()};

    const int chain_id{1};
    const uint64_t batch_size{256 * kMebi};
    BlockNum start_block{10};  // This does not exist, TestDatabaseContext db contains up to block 9
    BlockNum end_block{100};
    db::RWTxnManaged external_txn{db};
    const auto result0{
        silkworm_lib.execute_blocks(*external_txn, chain_id, start_block, end_block, batch_size,
                                    true, true, true)};
    CHECK_NOTHROW(external_txn.commit_and_stop());
    CHECK(result0.execute_block_result == SILKWORM_BLOCK_NOT_FOUND);
    CHECK(result0.last_executed_block == 0);
    CHECK(result0.mdbx_error_code == 0);
}

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_execute_blocks_perpetual: block not found", "[silkworm][capi]") {
    // Use Silkworm as a library with silkworm_init/silkworm_fini automated by RAII
    SilkwormLibrary silkworm_lib{db.get_path()};

    const int chain_id{1};
    const uint64_t batch_size{256 * kMebi};
    BlockNum start_block{10};  // This does not exist, TestDatabaseContext db contains up to block 9
    BlockNum end_block{100};
    const auto result0{
        silkworm_lib.execute_blocks_perpetual(db, chain_id, start_block, end_block, batch_size,
                                              true, true, true)};
    CHECK(result0.execute_block_result == SILKWORM_BLOCK_NOT_FOUND);
    CHECK(result0.last_executed_block == 0);
    CHECK(result0.mdbx_error_code == 0);
}

static void insert_block(mdbx::env& env, Block& block) {
    auto block_hash = block.header.hash();
    auto block_hash_key = db::block_key(block.header.number, block_hash.bytes);

    db::RWTxnManaged rw_txn{env};
    db::write_senders(rw_txn, block_hash, block.header.number, block);

    intx::uint256 max_priority_fee_per_gas =
        block.transactions.empty() ? block.header.base_fee_per_gas.value_or(0) : block.transactions[0].max_priority_fee_per_gas;
    intx::uint256 max_fee_per_gas =
        block.transactions.empty() ? block.header.base_fee_per_gas.value_or(0) : block.transactions[0].max_fee_per_gas;
    silkworm::Transaction system_transaction;
    system_transaction.max_priority_fee_per_gas = max_priority_fee_per_gas;
    system_transaction.max_fee_per_gas = max_fee_per_gas;
    block.transactions.emplace(block.transactions.begin(), system_transaction);
    block.transactions.emplace_back(system_transaction);

    db::write_header(rw_txn, block.header, true);
    db::write_raw_body(rw_txn, block, block_hash, block.header.number);
    db::write_canonical_header_hash(rw_txn, block_hash.bytes, block.header.number);
    rw_txn.commit_and_stop();
}

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_execute_blocks_ephemeral single block: OK", "[silkworm][capi]") {
    // Use Silkworm as a library with silkworm_init/silkworm_fini automated by RAII
    SilkwormLibrary silkworm_lib{db.get_path()};

    const int chain_id{1};
    const uint64_t batch_size{256 * kMebi};
    const bool write_change_sets{false};  // We CANNOT write changesets here, TestDatabaseContext db already has them
    const bool write_receipts{false};     // We CANNOT write receipts here, TestDatabaseContext db already has them
    const bool write_call_traces{false};  // For coherence but don't care

    auto execute_blocks = [&](auto tx, auto start_block, auto end_block) {
        return silkworm_lib.execute_blocks(tx,
                                           chain_id,
                                           start_block,
                                           end_block,
                                           batch_size,
                                           write_change_sets,
                                           write_receipts,
                                           write_call_traces);
    };

    /* TestDatabaseContext db contains a test chain made up of 9 blocks */

    // Prepare and insert block 10 (just 1 tx w/ value transfer)
    evmc::address from{0x658bdf435d810c91414ec09147daa6db62406379_address};  // funded in genesis
    evmc::address to{0x8b299e2b7d7f43c0ce3068263545309ff4ffb521_address};    // untouched address
    intx::uint256 value{1 * kEther};

    Block block{};
    block.header.number = 10;
    block.header.gas_limit = 5'000'000;
    block.header.gas_used = 21'000;

    static constexpr auto kEncoder = [](Bytes& dest, const Receipt& r) { rlp::encode(dest, r); };
    std::vector<Receipt> receipts{
        {TransactionType::kLegacy, true, block.header.gas_used, {}, {}},
    };
    block.header.receipts_root = trie::root_hash(receipts, kEncoder);
    block.transactions.resize(1);
    block.transactions[0].to = to;
    block.transactions[0].gas_limit = block.header.gas_limit;
    block.transactions[0].type = TransactionType::kLegacy;
    block.transactions[0].max_priority_fee_per_gas = 0;
    block.transactions[0].max_fee_per_gas = 20 * kGiga;
    block.transactions[0].value = value;
    block.transactions[0].r = 1;  // dummy
    block.transactions[0].s = 1;  // dummy
    block.transactions[0].set_sender(from);

    insert_block(db, block);

    // Execute block 11 using an *external* txn, then commit
    db::RWTxnManaged external_txn0{db};
    BlockNum start_block{10}, end_block{10};
    const auto result0{execute_blocks(*external_txn0, start_block, end_block)};
    CHECK_NOTHROW(external_txn0.commit_and_stop());
    CHECK(result0.execute_block_result == SILKWORM_OK);
    CHECK(result0.last_executed_block == end_block);
    CHECK(result0.mdbx_error_code == 0);

    db::ROTxnManaged ro_txn{db};
    REQUIRE(db::read_account(ro_txn, to));
    CHECK(db::read_account(ro_txn, to)->balance == value);
    ro_txn.abort();

    // Prepare and insert block 11 (same as block 10)
    block.transactions.erase(block.transactions.cbegin());
    block.transactions.pop_back();
    block.header.number = 11;
    block.transactions[0].nonce++;

    insert_block(db, block);

    // Execute block 11 using an *external* txn, then commit
    db::RWTxnManaged external_txn1{db};

    start_block = 11, end_block = 11;
    const auto result1{execute_blocks(*external_txn1, start_block, end_block)};
    CHECK_NOTHROW(external_txn1.commit_and_stop());
    CHECK(result1.execute_block_result == SILKWORM_OK);
    CHECK(result1.last_executed_block == end_block);
    CHECK(result1.mdbx_error_code == 0);

    ro_txn = db::ROTxnManaged{db};
    REQUIRE(db::read_account(ro_txn, to));
    CHECK(db::read_account(ro_txn, to)->balance == 2 * value);
}

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_execute_blocks_perpetual single block: OK", "[silkworm][capi]") {
    // Use Silkworm as a library with silkworm_init/silkworm_fini automated by RAII
    SilkwormLibrary silkworm_lib{db.get_path()};

    const int chain_id{1};
    const uint64_t batch_size{256 * kMebi};
    const bool write_change_sets{false};  // We CANNOT write changesets here, TestDatabaseContext db already has them
    const bool write_receipts{false};     // We CANNOT write receipts here, TestDatabaseContext db already has them
    const bool write_call_traces{false};  // For coherence but don't care

    auto execute_blocks = [&](auto start_block, auto end_block) {
        return silkworm_lib.execute_blocks_perpetual(db,
                                                     chain_id,
                                                     start_block,
                                                     end_block,
                                                     batch_size,
                                                     write_change_sets,
                                                     write_receipts,
                                                     write_call_traces);
    };

    /* TestDatabaseContext db contains a test chain made up of 9 blocks */

    // Prepare and insert block 10 (just 1 tx w/ value transfer)
    evmc::address from{0x658bdf435d810c91414ec09147daa6db62406379_address};  // funded in genesis
    evmc::address to{0x8b299e2b7d7f43c0ce3068263545309ff4ffb521_address};    // untouched address
    intx::uint256 value{1 * kEther};

    Block block{};
    block.header.number = 10;
    block.header.gas_limit = 5'000'000;
    block.header.gas_used = 21'000;

    static constexpr auto kEncoder = [](Bytes& dest, const Receipt& r) { rlp::encode(dest, r); };
    std::vector<Receipt> receipts{
        {TransactionType::kLegacy, true, block.header.gas_used, {}, {}},
    };
    block.header.receipts_root = trie::root_hash(receipts, kEncoder);
    block.transactions.resize(1);
    block.transactions[0].to = to;
    block.transactions[0].gas_limit = block.header.gas_limit;
    block.transactions[0].type = TransactionType::kLegacy;
    block.transactions[0].max_priority_fee_per_gas = 0;
    block.transactions[0].max_fee_per_gas = 20 * kGiga;
    block.transactions[0].value = value;
    block.transactions[0].r = 1;  // dummy
    block.transactions[0].s = 1;  // dummy
    block.transactions[0].set_sender(from);

    insert_block(db, block);

    // Execute block 10 using an *internal* txn
    BlockNum start_block{10}, end_block{10};
    const auto result0{execute_blocks(start_block, end_block)};
    CHECK(result0.execute_block_result == SILKWORM_OK);
    CHECK(result0.last_executed_block == end_block);
    CHECK(result0.mdbx_error_code == 0);

    db::ROTxnManaged ro_txn{db};
    REQUIRE(db::read_account(ro_txn, to));
    CHECK(db::read_account(ro_txn, to)->balance == value);
    ro_txn.abort();

    // Prepare and insert block 11 (same as block 10)
    block.transactions.erase(block.transactions.cbegin());
    block.transactions.pop_back();
    block.header.number = 11;
    block.transactions[0].nonce++;

    insert_block(db, block);

    // Execute block 11 using an *internal* txn
    start_block = 11, end_block = 11;
    const auto result1{execute_blocks(start_block, end_block)};
    CHECK(result1.execute_block_result == SILKWORM_OK);
    CHECK(result1.last_executed_block == end_block);
    CHECK(result1.mdbx_error_code == 0);

    ro_txn = db::ROTxnManaged{db};
    REQUIRE(db::read_account(ro_txn, to));
    CHECK(db::read_account(ro_txn, to)->balance == 2 * value);
}

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_execute_blocks_ephemeral multiple blocks: OK", "[silkworm][capi]") {
    // Use Silkworm as a library with silkworm_init/silkworm_fini automated by RAII
    SilkwormLibrary silkworm_lib{db.get_path()};

    const int chain_id{1};
    const uint64_t batch_size{256 * kMebi};
    const bool write_change_sets{false};  // We CANNOT write changesets here, TestDatabaseContext db already has them
    const bool write_receipts{false};     // We CANNOT write receipts here, TestDatabaseContext db already has them
    const bool write_call_traces{false};  // For coherence but don't care

    auto execute_blocks = [&](auto tx, auto start_block, auto end_block) {
        return silkworm_lib.execute_blocks(tx,
                                           chain_id,
                                           start_block,
                                           end_block,
                                           batch_size,
                                           write_change_sets,
                                           write_receipts,
                                           write_call_traces);
    };

    /* TestDatabaseContext db contains a test chain made up of 9 blocks */

    // Prepare block template (just 1 tx w/ value transfer)
    evmc::address from{0x658bdf435d810c91414ec09147daa6db62406379_address};  // funded in genesis
    evmc::address to{0x8b299e2b7d7f43c0ce3068263545309ff4ffb521_address};    // untouched address
    intx::uint256 value{1};

    Block block{};
    block.header.gas_limit = 5'000'000;
    block.header.gas_used = 21'000;

    static constexpr auto kEncoder = [](Bytes& dest, const Receipt& r) { rlp::encode(dest, r); };
    std::vector<Receipt> receipts{
        {TransactionType::kLegacy, true, block.header.gas_used, {}, {}},
    };
    block.header.receipts_root = trie::root_hash(receipts, kEncoder);
    block.transactions.resize(1);
    block.transactions[0].to = to;
    block.transactions[0].gas_limit = block.header.gas_limit;
    block.transactions[0].type = TransactionType::kLegacy;
    block.transactions[0].max_priority_fee_per_gas = 0;
    block.transactions[0].max_fee_per_gas = 20 * kGiga;
    block.transactions[0].value = value;
    block.transactions[0].r = 1;  // dummy
    block.transactions[0].s = 1;  // dummy
    block.transactions[0].set_sender(from);

    constexpr size_t kBlocks{130};

    // Insert N blocks
    for (size_t i{10}; i < 10 + kBlocks; ++i) {
        block.header.number = i;
        insert_block(db, block);
        block.transactions.erase(block.transactions.cbegin());
        block.transactions.pop_back();
        block.transactions[0].nonce++;
    }

    // Execute N blocks using an *external* txn, then commit
    db::RWTxnManaged external_txn0{db};
    BlockNum start_block{10}, end_block{10 + kBlocks - 1};
    const auto result0{execute_blocks(*external_txn0, start_block, end_block)};
    CHECK_NOTHROW(external_txn0.commit_and_stop());
    CHECK(result0.execute_block_result == SILKWORM_OK);
    CHECK(result0.last_executed_block == end_block);
    CHECK(result0.mdbx_error_code == 0);

    db::ROTxnManaged ro_txn{db};
    REQUIRE(db::read_account(ro_txn, to));
    CHECK(db::read_account(ro_txn, to)->balance == kBlocks * value);
    ro_txn.abort();

    // Insert N blocks again
    for (size_t i{10 + kBlocks}; i < (10 + 2 * kBlocks); ++i) {
        block.header.number = i;
        insert_block(db, block);
        block.transactions.erase(block.transactions.cbegin());
        block.transactions.pop_back();
        block.transactions[0].nonce++;
    }

    // Execute N blocks using an *external* txn, then commit
    db::RWTxnManaged external_txn1{db};

    start_block = 10 + kBlocks, end_block = 10 + 2 * kBlocks - 1;
    const auto result1{execute_blocks(*external_txn1, start_block, end_block)};
    CHECK_NOTHROW(external_txn1.commit_and_stop());
    CHECK(result1.execute_block_result == SILKWORM_OK);
    CHECK(result1.last_executed_block == end_block);
    CHECK(result1.mdbx_error_code == 0);

    ro_txn = db::ROTxnManaged{db};
    REQUIRE(db::read_account(ro_txn, to));
    CHECK(db::read_account(ro_txn, to)->balance == 2 * kBlocks * value);
}

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_execute_blocks_perpetual multiple blocks: OK", "[silkworm][capi]") {
    // Use Silkworm as a library with silkworm_init/silkworm_fini automated by RAII
    SilkwormLibrary silkworm_lib{db.get_path()};

    const int chain_id{1};
    const uint64_t batch_size{256 * kMebi};
    const bool write_change_sets{false};  // We CANNOT write changesets here, TestDatabaseContext db already has them
    const bool write_receipts{false};     // We CANNOT write receipts here, TestDatabaseContext db already has them
    const bool write_call_traces{false};  // For coherence but don't care

    auto execute_blocks = [&](auto start_block, auto end_block) {
        return silkworm_lib.execute_blocks_perpetual(db,
                                                     chain_id,
                                                     start_block,
                                                     end_block,
                                                     batch_size,
                                                     write_change_sets,
                                                     write_receipts,
                                                     write_call_traces);
    };

    /* TestDatabaseContext db contains a test chain made up of 9 blocks */

    // Prepare block template (just 1 tx w/ value transfer)
    evmc::address from{0x658bdf435d810c91414ec09147daa6db62406379_address};  // funded in genesis
    evmc::address to{0x8b299e2b7d7f43c0ce3068263545309ff4ffb521_address};    // untouched address
    intx::uint256 value{1};

    Block block{};
    block.header.gas_limit = 5'000'000;
    block.header.gas_used = 21'000;

    static constexpr auto kEncoder = [](Bytes& dest, const Receipt& r) { rlp::encode(dest, r); };
    std::vector<Receipt> receipts{
        {TransactionType::kLegacy, true, block.header.gas_used, {}, {}},
    };
    block.header.receipts_root = trie::root_hash(receipts, kEncoder);
    block.transactions.resize(1);
    block.transactions[0].to = to;
    block.transactions[0].gas_limit = block.header.gas_limit;
    block.transactions[0].type = TransactionType::kLegacy;
    block.transactions[0].max_priority_fee_per_gas = 0;
    block.transactions[0].max_fee_per_gas = 20 * kGiga;
    block.transactions[0].value = value;
    block.transactions[0].r = 1;  // dummy
    block.transactions[0].s = 1;  // dummy
    block.transactions[0].set_sender(from);

    constexpr size_t kBlocks{130};

    // Insert N blocks
    for (size_t i{10}; i < 10 + kBlocks; ++i) {
        block.header.number = i;
        insert_block(db, block);
        block.transactions.erase(block.transactions.cbegin());
        block.transactions.pop_back();
        block.transactions[0].nonce++;
    }

    // Execute N blocks using an *internal* txn
    BlockNum start_block{10}, end_block{10 + kBlocks - 1};
    const auto result0{execute_blocks(start_block, end_block)};
    CHECK(result0.execute_block_result == SILKWORM_OK);
    CHECK(result0.last_executed_block == end_block);
    CHECK(result0.mdbx_error_code == 0);

    db::ROTxnManaged ro_txn{db};
    REQUIRE(db::read_account(ro_txn, to));
    CHECK(db::read_account(ro_txn, to)->balance == kBlocks * value);
    ro_txn.abort();

    // Insert N blocks again
    for (size_t i{10 + kBlocks}; i < (10 + 2 * kBlocks); ++i) {
        block.header.number = i;
        insert_block(db, block);
        block.transactions.erase(block.transactions.cbegin());
        block.transactions.pop_back();
        block.transactions[0].nonce++;
    }

    // Execute N blocks using an *internal* txn, then commit
    start_block = 10 + kBlocks, end_block = 10 + 2 * kBlocks - 1;
    const auto result1{execute_blocks(start_block, end_block)};
    CHECK(result1.execute_block_result == SILKWORM_OK);
    CHECK(result1.last_executed_block == end_block);
    CHECK(result1.mdbx_error_code == 0);

    ro_txn = db::ROTxnManaged{db};
    REQUIRE(db::read_account(ro_txn, to));
    CHECK(db::read_account(ro_txn, to)->balance == 2 * kBlocks * value);
}

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_add_snapshot", "[silkworm][capi]") {
    snapshot_test::SampleHeaderSnapshotFile valid_header_snapshot{};
    snapshot_test::SampleHeaderSnapshotPath header_snapshot_path{valid_header_snapshot.path()};
    snapshot_test::SampleBodySnapshotFile valid_body_snapshot{};
    snapshot_test::SampleBodySnapshotPath body_snapshot_path{valid_body_snapshot.path()};
    snapshot_test::SampleTransactionSnapshotFile valid_tx_snapshot{};
    snapshot_test::SampleTransactionSnapshotPath tx_snapshot_path{valid_tx_snapshot.path()};

    snapshots::HeaderIndex header_index{header_snapshot_path};
    REQUIRE_NOTHROW(header_index.build());
    snapshots::HeaderSnapshot header_snapshot{header_snapshot_path};
    header_snapshot.reopen_segment();
    header_snapshot.reopen_index();
    snapshots::BodyIndex body_index{body_snapshot_path};
    REQUIRE_NOTHROW(body_index.build());
    snapshots::BodySnapshot body_snapshot{body_snapshot_path};
    body_snapshot.reopen_segment();
    body_snapshot.reopen_index();
    snapshots::TransactionIndex tx_index{tx_snapshot_path};
    REQUIRE_NOTHROW(tx_index.build());
    snapshots::TransactionSnapshot tx_snapshot{tx_snapshot_path};
    tx_snapshot.reopen_segment();
    tx_snapshot.reopen_index();

    const auto header_snapshot_path_string{header_snapshot_path.path().string()};
    const auto header_index_path_string{header_index.path().path().string()};
    const auto body_snapshot_path_string{body_snapshot_path.path().string()};
    const auto body_index_path_string{body_index.path().path().string()};
    const auto tx_snapshot_path_string{tx_snapshot_path.path().string()};
    const auto tx_hash_index_path_string{tx_snapshot_path.index_file().path().string()};
    const auto tx_hash2block_index_path_string{
        tx_snapshot_path.index_file_for_type(snapshots::SnapshotType::transactions_to_block).path().string()};

    // Prepare templates for valid header/body/transaction C data structures
    SilkwormHeadersSnapshot valid_shs{
        .segment = SilkwormMemoryMappedFile{
            .file_path = header_snapshot_path_string.c_str(),
            .memory_address = header_snapshot.memory_file_address(),
            .memory_length = header_snapshot.memory_file_size(),
        },
        .header_hash_index = SilkwormMemoryMappedFile{
            .file_path = header_index_path_string.c_str(),
            .memory_address = header_snapshot.idx_header_hash()->memory_file_address(),
            .memory_length = header_snapshot.idx_header_hash()->memory_file_size(),
        },
    };
    SilkwormBodiesSnapshot valid_sbs{
        .segment = SilkwormMemoryMappedFile{
            .file_path = body_snapshot_path_string.c_str(),
            .memory_address = body_snapshot.memory_file_address(),
            .memory_length = body_snapshot.memory_file_size(),
        },
        .block_num_index = SilkwormMemoryMappedFile{
            .file_path = body_index_path_string.c_str(),
            .memory_address = body_snapshot.idx_body_number()->memory_file_address(),
            .memory_length = body_snapshot.idx_body_number()->memory_file_size(),
        },
    };
    SilkwormTransactionsSnapshot valid_sts{
        .segment = SilkwormMemoryMappedFile{
            .file_path = tx_snapshot_path_string.c_str(),
            .memory_address = tx_snapshot.memory_file_address(),
            .memory_length = tx_snapshot.memory_file_size(),
        },
        .tx_hash_index = SilkwormMemoryMappedFile{
            .file_path = tx_hash_index_path_string.c_str(),
            .memory_address = tx_snapshot.idx_txn_hash()->memory_file_address(),
            .memory_length = tx_snapshot.idx_txn_hash()->memory_file_size(),
        },
        .tx_hash_2_block_index = SilkwormMemoryMappedFile{
            .file_path = tx_hash2block_index_path_string.c_str(),
            .memory_address = tx_snapshot.idx_txn_hash_2_block()->memory_file_address(),
            .memory_length = tx_snapshot.idx_txn_hash_2_block()->memory_file_size(),
        },
    };

    SECTION("invalid handle") {
        // We purposely do not call silkworm_init to provide a null handle
        SilkwormHandle handle{nullptr};
        SilkwormChainSnapshot snapshot{valid_shs, valid_sbs, valid_sts};
        CHECK(silkworm_add_snapshot(handle, &snapshot) == SILKWORM_INVALID_HANDLE);
    }

    // Use Silkworm as a library with silkworm_init/silkworm_fini automated by RAII
    SilkwormLibrary silkworm_lib{db.get_path()};

    SECTION("invalid header segment path") {
        SilkwormHeadersSnapshot invalid_shs{valid_shs};
        invalid_shs.segment.file_path = nullptr;  // as if left unassigned, i.e. empty
        SilkwormChainSnapshot snapshot{invalid_shs, valid_sbs, valid_sts};
        const int result{silkworm_lib.add_snapshot(&snapshot)};
        CHECK(result == SILKWORM_INVALID_PATH);
    }
    SECTION("invalid header index path") {
        SilkwormHeadersSnapshot invalid_shs{valid_shs};
        invalid_shs.header_hash_index.file_path = nullptr;  // as if left unassigned, i.e. empty
        SilkwormChainSnapshot snapshot{invalid_shs, valid_sbs, valid_sts};
        const int result{silkworm_lib.add_snapshot(&snapshot)};
        CHECK(result == SILKWORM_INVALID_PATH);
    }
    SECTION("invalid body segment path") {
        SilkwormBodiesSnapshot invalid_sbs{valid_sbs};
        invalid_sbs.segment.file_path = nullptr;  // as if left unassigned, i.e. empty
        SilkwormChainSnapshot snapshot{valid_shs, invalid_sbs, valid_sts};
        const int result{silkworm_lib.add_snapshot(&snapshot)};
        CHECK(result == SILKWORM_INVALID_PATH);
    }
    SECTION("invalid body index path") {
        SilkwormBodiesSnapshot invalid_sbs{valid_sbs};
        invalid_sbs.block_num_index.file_path = nullptr;  // as if left unassigned, i.e. empty
        SilkwormChainSnapshot snapshot{valid_shs, invalid_sbs, valid_sts};
        const int result{silkworm_lib.add_snapshot(&snapshot)};
        CHECK(result == SILKWORM_INVALID_PATH);
    }
    SECTION("invalid transaction segment path") {
        SilkwormTransactionsSnapshot invalid_sts{valid_sts};
        invalid_sts.segment.file_path = nullptr;  // as if left unassigned, i.e. empty
        SilkwormChainSnapshot snapshot{valid_shs, valid_sbs, invalid_sts};
        const int result{silkworm_lib.add_snapshot(&snapshot)};
        CHECK(result == SILKWORM_INVALID_PATH);
    }
    SECTION("invalid transaction hash index path") {
        SilkwormTransactionsSnapshot invalid_sts{valid_sts};
        invalid_sts.tx_hash_index.file_path = nullptr;  // as if left unassigned, i.e. empty
        SilkwormChainSnapshot snapshot{valid_shs, valid_sbs, invalid_sts};
        const int result{silkworm_lib.add_snapshot(&snapshot)};
        CHECK(result == SILKWORM_INVALID_PATH);
    }
    SECTION("invalid transaction hash2block index path") {
        SilkwormTransactionsSnapshot invalid_sts{valid_sts};
        invalid_sts.tx_hash_2_block_index.file_path = nullptr;  // as if left unassigned, i.e. empty
        SilkwormChainSnapshot snapshot{valid_shs, valid_sbs, invalid_sts};
        const int result{silkworm_lib.add_snapshot(&snapshot)};
        CHECK(result == SILKWORM_INVALID_PATH);
    }
    SECTION("invalid empty chain snapshot") {
        SilkwormChainSnapshot snapshot{};
        const int result{silkworm_lib.add_snapshot(&snapshot)};
        CHECK(result == SILKWORM_INVALID_PATH);
    }
    SECTION("valid") {
        SilkwormChainSnapshot snapshot{valid_shs, valid_sbs, valid_sts};
        const int result{silkworm_lib.add_snapshot(&snapshot)};
        CHECK(result == SILKWORM_OK);
    }
}

}  // namespace silkworm
