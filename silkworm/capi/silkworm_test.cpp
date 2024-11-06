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

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/test_util/sample_blocks.hpp>
#include <silkworm/core/trie/vector_root.hpp>
#include <silkworm/db/blocks/bodies/body_index.hpp>
#include <silkworm/db/blocks/headers/header_index.hpp>
#include <silkworm/db/datastore/mdbx/mdbx.hpp>
#include <silkworm/db/datastore/snapshots/index_builder.hpp>
#include <silkworm/db/datastore/snapshots/segment/segment_reader.hpp>
#include <silkworm/db/test_util/temp_snapshots.hpp>
#include <silkworm/db/transactions/txn_index.hpp>
#include <silkworm/db/transactions/txn_to_block_index.hpp>
#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/common/environment.hpp>
#include <silkworm/rpc/test_util/api_test_database.hpp>

#include "instance.hpp"

namespace silkworm {

namespace snapshot_test = snapshots::test_util;
using namespace silkworm::db;

struct CApiTest {
    TemporaryDirectory tmp_dir;
    db::test_util::TestDatabaseContext database{tmp_dir};

    SilkwormSettings settings{.log_verbosity = SilkwormLogLevel::SILKWORM_LOG_NONE};
    mdbx::env env{*database.chaindata_rw()};
    const std::filesystem::path& env_path() { return database.chaindata_dir_path(); }
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
    SilkwormHandle handle{nullptr};
    CHECK(silkworm_init(&handle, &settings) == SILKWORM_INVALID_PATH);
    CHECK(!handle);
}

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_init: empty data folder path", "[silkworm][capi]") {
    copy_path(settings.data_dir_path, "");
    copy_git_version(settings.libmdbx_version, silkworm_libmdbx_version());
    SilkwormHandle handle{nullptr};
    CHECK(silkworm_init(&handle, &settings) == SILKWORM_INVALID_PATH);
    CHECK(!handle);
}

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_init: empty MDBX version", "[silkworm][capi]") {
    copy_path(settings.data_dir_path, env_path().string().c_str());
    copy_git_version(settings.libmdbx_version, "");
    SilkwormHandle handle{nullptr};
    CHECK(silkworm_init(&handle, &settings) == SILKWORM_INCOMPATIBLE_LIBMDBX);
    CHECK(!handle);
}

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_init: incompatible MDBX version", "[silkworm][capi]") {
    copy_path(settings.data_dir_path, env_path().string().c_str());
    copy_git_version(settings.libmdbx_version, "v0.1.0");
    SilkwormHandle handle{nullptr};
    CHECK(silkworm_init(&handle, &settings) == SILKWORM_INCOMPATIBLE_LIBMDBX);
    CHECK(!handle);
}

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_init: OK", "[silkworm][capi]") {
    copy_path(settings.data_dir_path, env_path().string().c_str());
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
    copy_path(settings.data_dir_path, env_path().string().c_str());
    copy_git_version(settings.libmdbx_version, silkworm_libmdbx_version());
    SilkwormHandle handle{nullptr};
    REQUIRE(silkworm_init(&handle, &settings) == SILKWORM_OK);
    CHECK(silkworm_fini(handle) == SILKWORM_OK);
}

//! \brief Utility class using RAII pattern to wrap the Silkworm C API.
//! \note This is useful for tests that do *not* specifically play with silkworm_init/silkworm_fini or invalid handles
struct SilkwormLibrary {
    explicit SilkwormLibrary(const std::filesystem::path& env_path) {
        SilkwormSettings settings{.log_verbosity = SilkwormLogLevel::SILKWORM_LOG_NONE};
        copy_path(settings.data_dir_path, env_path.string().c_str());
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
                                   bool write_call_traces) const {
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
                                             bool write_call_traces) const {
        ExecutionResult result;
        result.execute_block_result =
            silkworm_execute_blocks_perpetual(handle_, env,
                                              chain_id, start_block, max_block, batch_size,
                                              write_change_sets, write_receipts, write_call_traces,
                                              &result.last_executed_block, &result.mdbx_error_code);
        return result;
    }

    int add_snapshot(SilkwormChainSnapshot* snapshot) const {
        return silkworm_add_snapshot(handle_, snapshot);
    }

    int start_rpcdaemon(MDBX_env* env, const SilkwormRpcSettings* settings) const {
        return silkworm_start_rpcdaemon(handle_, env, settings);
    }

    int stop_rpcdaemon() const {
        return silkworm_stop_rpcdaemon(handle_);
    }

    int start_fork_validator(MDBX_env* env, const SilkwormForkValidatorSettings* settings) const {
        return silkworm_start_fork_validator(handle_, env, settings);
    }

    int stop_fork_validator() const {
        return silkworm_stop_fork_validator(handle_);
    }

    int fork_validator_verify_chain(silkworm::Hash head_hash) const {
        SilkwormBytes32 head_hash_bytes{};
        std::memcpy(head_hash_bytes.bytes, head_hash.bytes, 32);

        auto result = std::make_unique<SilkwormForkValidatorValidationResult>();

        return silkworm_fork_validator_verify_chain(handle_, head_hash_bytes, result.get());
    }

    int execution_engine_fork_choice_update(silkworm::Hash head_hash, silkworm::Hash finalized_hash, silkworm::Hash safe_hash) const {
        SilkwormBytes32 head_hash_bytes{}, finalized_hash_bytes{}, safe_hash_bytes{};
        std::memcpy(head_hash_bytes.bytes, head_hash.bytes, 32);
        std::memcpy(finalized_hash_bytes.bytes, finalized_hash.bytes, 32);
        std::memcpy(safe_hash_bytes.bytes, safe_hash.bytes, 32);
        return silkworm_fork_validator_fork_choice_update(handle_, head_hash_bytes, finalized_hash_bytes, safe_hash_bytes);
    }

    silkworm::stagedsync::ExecutionEngine& execution_engine() const {
        return *(handle_->execution_engine);
    }

  private:
    SilkwormHandle handle_{nullptr};
};

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_execute_blocks_ephemeral: block not found", "[silkworm][capi]") {
    // Use Silkworm as a library with silkworm_init/silkworm_fini automated by RAII
    SilkwormLibrary silkworm_lib{env_path()};

    const int chain_id{1};
    const uint64_t batch_size{256 * kMebi};
    BlockNum start_block{10};  // This does not exist, TestDatabaseContext db contains up to block 9
    BlockNum end_block{100};
    RWTxnManaged external_txn{env};
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
    SilkwormLibrary silkworm_lib{env_path()};

    const int chain_id{1};
    const uint64_t batch_size{256 * kMebi};
    BlockNum start_block{10};  // This does not exist, TestDatabaseContext db contains up to block 9
    BlockNum end_block{100};
    const auto result0{
        silkworm_lib.execute_blocks_perpetual(env, chain_id, start_block, end_block, batch_size,
                                              true, true, true)};
    CHECK(result0.execute_block_result == SILKWORM_BLOCK_NOT_FOUND);
    CHECK(result0.last_executed_block == 0);
    CHECK(result0.mdbx_error_code == 0);
}

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_execute_blocks_ephemeral: chain id not found", "[silkworm][capi]") {
    // Use Silkworm as a library with silkworm_init/silkworm_fini automated by RAII
    SilkwormLibrary silkworm_lib{env_path()};

    const uint64_t chain_id{1000000};
    const uint64_t batch_size{256 * kMebi};
    BlockNum start_block{1};
    BlockNum end_block{2};
    RWTxnManaged external_txn{env};
    const auto result0{
        silkworm_lib.execute_blocks(*external_txn, chain_id, start_block, end_block, batch_size,
                                    true, true, true)};
    CHECK_NOTHROW(external_txn.commit_and_stop());
    CHECK(result0.execute_block_result == SILKWORM_UNKNOWN_CHAIN_ID);
    CHECK(result0.last_executed_block == 0);
    CHECK(result0.mdbx_error_code == 0);
}

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_execute_blocks_perpetual: chain id not found", "[silkworm][capi]") {
    // Use Silkworm as a library with silkworm_init/silkworm_fini automated by RAII
    SilkwormLibrary silkworm_lib{env_path()};

    const uint64_t chain_id{1000000};
    const uint64_t batch_size{256 * kMebi};
    BlockNum start_block{1};
    BlockNum end_block{2};
    const auto result0{
        silkworm_lib.execute_blocks_perpetual(env, chain_id, start_block, end_block, batch_size,
                                              true, true, true)};
    CHECK(result0.execute_block_result == SILKWORM_UNKNOWN_CHAIN_ID);
    CHECK(result0.last_executed_block == 0);
    CHECK(result0.mdbx_error_code == 0);
}

static void insert_block(mdbx::env& env, Block& block) {
    auto block_hash = block.header.hash();

    RWTxnManaged rw_txn{env};
    write_senders(rw_txn, block_hash, block.header.number, block);

    intx::uint256 max_priority_fee_per_gas =
        block.transactions.empty() ? block.header.base_fee_per_gas.value_or(0) : block.transactions[0].max_priority_fee_per_gas;
    intx::uint256 max_fee_per_gas =
        block.transactions.empty() ? block.header.base_fee_per_gas.value_or(0) : block.transactions[0].max_fee_per_gas;
    silkworm::Transaction system_transaction;
    system_transaction.max_priority_fee_per_gas = max_priority_fee_per_gas;
    system_transaction.max_fee_per_gas = max_fee_per_gas;
    block.transactions.emplace(block.transactions.begin(), system_transaction);
    block.transactions.emplace_back(system_transaction);

    write_header(rw_txn, block.header, true);
    write_raw_body(rw_txn, block, block_hash, block.header.number);
    write_canonical_header_hash(rw_txn, block_hash.bytes, block.header.number);
    rw_txn.commit_and_stop();
}

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_execute_blocks_ephemeral single block: OK", "[silkworm][capi]") {
    // Use Silkworm as a library with silkworm_init/silkworm_fini automated by RAII
    SilkwormLibrary silkworm_lib{env_path()};

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

    insert_block(env, block);

    // Execute block 11 using an *external* txn, then commit
    RWTxnManaged external_txn0{env};
    BlockNum start_block{10}, end_block{10};
    const auto result0{execute_blocks(*external_txn0, start_block, end_block)};
    CHECK_NOTHROW(external_txn0.commit_and_stop());
    CHECK(result0.execute_block_result == SILKWORM_OK);
    CHECK(result0.last_executed_block == end_block);
    CHECK(result0.mdbx_error_code == 0);

    ROTxnManaged ro_txn{env};
    REQUIRE(read_account(ro_txn, to));
    CHECK(read_account(ro_txn, to)->balance == value);
    ro_txn.abort();

    // Prepare and insert block 11 (same as block 10)
    block.transactions.erase(block.transactions.cbegin());
    block.transactions.pop_back();
    block.header.number = 11;
    ++block.transactions[0].nonce;

    insert_block(env, block);

    // Execute block 11 using an *external* txn, then commit
    RWTxnManaged external_txn1{env};

    start_block = 11, end_block = 11;
    const auto result1{execute_blocks(*external_txn1, start_block, end_block)};
    CHECK_NOTHROW(external_txn1.commit_and_stop());
    CHECK(result1.execute_block_result == SILKWORM_OK);
    CHECK(result1.last_executed_block == end_block);
    CHECK(result1.mdbx_error_code == 0);

    ro_txn = ROTxnManaged{env};
    REQUIRE(read_account(ro_txn, to));
    CHECK(read_account(ro_txn, to)->balance == 2 * value);
}

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_execute_blocks_perpetual single block: OK", "[silkworm][capi]") {
    // Use Silkworm as a library with silkworm_init/silkworm_fini automated by RAII
    SilkwormLibrary silkworm_lib{env_path()};

    const int chain_id{1};
    const uint64_t batch_size{256 * kMebi};
    const bool write_change_sets{false};  // We CANNOT write changesets here, TestDatabaseContext db already has them
    const bool write_receipts{false};     // We CANNOT write receipts here, TestDatabaseContext db already has them
    const bool write_call_traces{false};  // For coherence but don't care

    auto execute_blocks = [&](auto start_block, auto end_block) {
        return silkworm_lib.execute_blocks_perpetual(env,
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

    insert_block(env, block);

    // Execute block 10 using an *internal* txn
    BlockNum start_block{10}, end_block{10};
    const auto result0{execute_blocks(start_block, end_block)};
    CHECK(result0.execute_block_result == SILKWORM_OK);
    CHECK(result0.last_executed_block == end_block);
    CHECK(result0.mdbx_error_code == 0);

    ROTxnManaged ro_txn{env};
    REQUIRE(read_account(ro_txn, to));
    CHECK(read_account(ro_txn, to)->balance == value);
    ro_txn.abort();

    // Prepare and insert block 11 (same as block 10)
    block.transactions.erase(block.transactions.cbegin());
    block.transactions.pop_back();
    block.header.number = 11;
    ++block.transactions[0].nonce;

    insert_block(env, block);

    // Execute block 11 using an *internal* txn
    start_block = 11, end_block = 11;
    const auto result1{execute_blocks(start_block, end_block)};
    CHECK(result1.execute_block_result == SILKWORM_OK);
    CHECK(result1.last_executed_block == end_block);
    CHECK(result1.mdbx_error_code == 0);

    ro_txn = ROTxnManaged{env};
    REQUIRE(read_account(ro_txn, to));
    CHECK(read_account(ro_txn, to)->balance == 2 * value);
}

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_execute_blocks_ephemeral multiple blocks: OK", "[silkworm][capi]") {
    // Use Silkworm as a library with silkworm_init/silkworm_fini automated by RAII
    SilkwormLibrary silkworm_lib{env_path()};

    const int chain_id{1};
    const uint64_t batch_size{3000};      // Small batch size to force multiple iterations
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
        insert_block(env, block);
        block.transactions.erase(block.transactions.cbegin());
        block.transactions.pop_back();
        ++block.transactions[0].nonce;
    }

    // Execute N blocks using an *external* txn, then commit
    RWTxnManaged external_txn0{env};
    BlockNum start_block{10}, end_block{10 + kBlocks - 1};
    const auto result0{execute_blocks(*external_txn0, start_block, end_block)};
    CHECK_NOTHROW(external_txn0.commit_and_stop());
    CHECK(result0.execute_block_result == SILKWORM_OK);
    CHECK(result0.last_executed_block == end_block);
    CHECK(result0.mdbx_error_code == 0);

    ROTxnManaged ro_txn{env};
    REQUIRE(read_account(ro_txn, to));
    CHECK(read_account(ro_txn, to)->balance == kBlocks * value);
    ro_txn.abort();

    // Insert N blocks again
    for (size_t i{10 + kBlocks}; i < (10 + 2 * kBlocks); ++i) {
        block.header.number = i;
        insert_block(env, block);
        block.transactions.erase(block.transactions.cbegin());
        block.transactions.pop_back();
        ++block.transactions[0].nonce;
    }

    // Execute N blocks using an *external* txn, then commit
    RWTxnManaged external_txn1{env};

    start_block = 10 + kBlocks, end_block = 10 + 2 * kBlocks - 1;
    const auto result1{execute_blocks(*external_txn1, start_block, end_block)};
    CHECK_NOTHROW(external_txn1.commit_and_stop());
    CHECK(result1.execute_block_result == SILKWORM_OK);
    CHECK(result1.last_executed_block == end_block);
    CHECK(result1.mdbx_error_code == 0);

    ro_txn = ROTxnManaged{env};
    REQUIRE(read_account(ro_txn, to));
    CHECK(read_account(ro_txn, to)->balance == 2 * kBlocks * value);
}

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_execute_blocks_perpetual multiple blocks: OK", "[silkworm][capi]") {
    // Use Silkworm as a library with silkworm_init/silkworm_fini automated by RAII
    SilkwormLibrary silkworm_lib{env_path()};

    const int chain_id{1};
    const uint64_t batch_size{3000};      // Small batch size to force multiple iterations
    const bool write_change_sets{false};  // We CANNOT write changesets here, TestDatabaseContext db already has them
    const bool write_receipts{false};     // We CANNOT write receipts here, TestDatabaseContext db already has them
    const bool write_call_traces{false};  // For coherence but don't care

    auto execute_blocks = [&](auto start_block, auto end_block) {
        return silkworm_lib.execute_blocks_perpetual(env,
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
    evmc::address to{0x8b299e2b7d7f43c0ce3068263545309ff4ffb500_address};    // untouched address(es)
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
        insert_block(env, block);
        block.transactions.erase(block.transactions.cbegin());
        block.transactions.pop_back();
        ++block.transactions[0].nonce;
        ++block.transactions[0].to->bytes[19];  // change recipient address to force batch size growth
    }

    // Execute N blocks using an *internal* txn
    BlockNum start_block{10}, end_block{10 + kBlocks - 1};
    const auto result0{execute_blocks(start_block, end_block)};
    CHECK(result0.execute_block_result == SILKWORM_OK);
    CHECK(result0.last_executed_block == end_block);
    CHECK(result0.mdbx_error_code == 0);

    ROTxnManaged ro_txn{env};
    REQUIRE(read_account(ro_txn, to));
    CHECK(read_account(ro_txn, to)->balance == value);
    ro_txn.abort();

    // Insert N blocks again
    block.transactions[0].to = to;
    for (size_t i{10 + kBlocks}; i < (10 + 2 * kBlocks); ++i) {
        block.header.number = i;
        insert_block(env, block);
        block.transactions.erase(block.transactions.cbegin());
        block.transactions.pop_back();
        ++block.transactions[0].nonce;
        ++block.transactions[0].to->bytes[19];  // change recipient address to force batch size growth
    }

    // Execute N blocks using an *internal* txn, then commit
    start_block = 10 + kBlocks, end_block = 10 + 2 * kBlocks - 1;
    const auto result1{execute_blocks(start_block, end_block)};
    CHECK(result1.execute_block_result == SILKWORM_OK);
    CHECK(result1.last_executed_block == end_block);
    CHECK(result1.mdbx_error_code == 0);

    ro_txn = ROTxnManaged{env};
    REQUIRE(read_account(ro_txn, to));
    CHECK(read_account(ro_txn, to)->balance == 2 * value);
}

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_execute_blocks_ephemeral multiple blocks: insufficient buffer", "[silkworm][capi]") {
    // Use Silkworm as a library with silkworm_init/silkworm_fini automated by RAII
    SilkwormLibrary silkworm_lib{env_path()};

    const int chain_id{1};
    const uint64_t batch_size{170};       // Small batch size to force multiple iterations
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
        insert_block(env, block);
        block.transactions.erase(block.transactions.cbegin());
        block.transactions.pop_back();
        ++block.transactions[0].nonce;
    }

    // Execute N blocks using an *external* txn, then commit
    RWTxnManaged external_txn0{env};
    BlockNum start_block{10}, end_block{10 + kBlocks - 1};
    const auto result0{execute_blocks(*external_txn0, start_block, end_block)};
    CHECK_NOTHROW(external_txn0.commit_and_stop());
    CHECK(result0.execute_block_result == SILKWORM_INTERNAL_ERROR);
}

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_execute_blocks_perpetual multiple blocks: insufficient buffer", "[silkworm][capi]") {
    // Use Silkworm as a library with silkworm_init/silkworm_fini automated by RAII
    SilkwormLibrary silkworm_lib{env_path()};

    const int chain_id{1};
    const uint64_t batch_size{170};       // Batch size not enough to process a single block
    const bool write_change_sets{false};  // We CANNOT write changesets here, TestDatabaseContext db already has them
    const bool write_receipts{false};     // We CANNOT write receipts here, TestDatabaseContext db already has them
    const bool write_call_traces{false};  // For coherence but don't care

    auto execute_blocks = [&](auto start_block, auto end_block) {
        return silkworm_lib.execute_blocks_perpetual(env,
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
    evmc::address to{0x8b299e2b7d7f43c0ce3068263545309ff4ffb500_address};    // untouched address(es)
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
        insert_block(env, block);
        block.transactions.erase(block.transactions.cbegin());
        block.transactions.pop_back();
        ++block.transactions[0].nonce;
        ++block.transactions[0].to->bytes[19];  // change recipient address to force batch size growth
    }

    // Execute N blocks using an *internal* txn
    BlockNum start_block{10}, end_block{10 + kBlocks - 1};
    const auto result0{execute_blocks(start_block, end_block)};
    CHECK(result0.execute_block_result == SILKWORM_INTERNAL_ERROR);
}

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_add_snapshot", "[silkworm][capi]") {
    snapshot_test::SampleHeaderSnapshotFile header_segment_file{tmp_dir.path()};
    auto& header_segment_path = header_segment_file.path();
    snapshot_test::SampleBodySnapshotFile body_segment_file{tmp_dir.path()};
    auto& body_segment_path = body_segment_file.path();
    snapshot_test::SampleTransactionSnapshotFile txn_segment_file{tmp_dir.path()};
    auto& txn_segment_path = txn_segment_file.path();

    auto header_index_builder = snapshots::HeaderIndex::make(header_segment_path);
    header_index_builder.set_base_data_id(header_segment_file.block_num_range().start);
    REQUIRE_NOTHROW(header_index_builder.build());
    snapshots::SegmentFileReader header_segment{header_segment_path};
    header_segment.reopen_segment();
    snapshots::Index idx_header_hash{header_segment_path.index_file()};
    idx_header_hash.reopen_index();

    auto body_index_builder = snapshots::BodyIndex::make(body_segment_path);
    body_index_builder.set_base_data_id(body_segment_file.block_num_range().start);
    REQUIRE_NOTHROW(body_index_builder.build());
    snapshots::SegmentFileReader body_segment{body_segment_path};
    body_segment.reopen_segment();
    snapshots::Index idx_body_number{body_segment_path.index_file()};
    idx_body_number.reopen_index();

    auto tx_index_builder = snapshots::TransactionIndex::make(body_segment_path, txn_segment_path);
    tx_index_builder.build();
    auto tx_index_hash_to_block_builder = snapshots::TransactionToBlockIndex::make(body_segment_path, txn_segment_path, txn_segment_file.block_num_range().start);
    tx_index_hash_to_block_builder.build();
    snapshots::SegmentFileReader txn_segment{txn_segment_path};
    txn_segment.reopen_segment();
    snapshots::Index idx_txn_hash{txn_segment_path.index_file()};
    idx_txn_hash.reopen_index();
    snapshots::Index idx_txn_hash_2_block{tx_index_hash_to_block_builder.path()};
    idx_txn_hash_2_block.reopen_index();

    const auto header_segment_path_string{header_segment_path.path().string()};
    const auto header_index_path_string{idx_header_hash.path().path().string()};
    const auto body_segment_path_string{body_segment_path.path().string()};
    const auto body_index_path_string{idx_body_number.path().path().string()};
    const auto txn_segment_path_string{txn_segment_path.path().string()};
    const auto tx_hash_index_path_string{idx_txn_hash.path().path().string()};
    const auto tx_hash2block_index_path_string{idx_txn_hash_2_block.path().path().string()};

    // Prepare templates for valid header/body/transaction C data structures
    SilkwormHeadersSnapshot valid_shs{
        .segment = SilkwormMemoryMappedFile{
            .file_path = header_segment_path_string.c_str(),
            .memory_address = header_segment.memory_file_region().data(),
            .memory_length = header_segment.memory_file_region().size(),
        },
        .header_hash_index = SilkwormMemoryMappedFile{
            .file_path = header_index_path_string.c_str(),
            .memory_address = idx_header_hash.memory_file_region().data(),
            .memory_length = idx_header_hash.memory_file_region().size(),
        },
    };
    SilkwormBodiesSnapshot valid_sbs{
        .segment = SilkwormMemoryMappedFile{
            .file_path = body_segment_path_string.c_str(),
            .memory_address = body_segment.memory_file_region().data(),
            .memory_length = body_segment.memory_file_region().size(),
        },
        .block_num_index = SilkwormMemoryMappedFile{
            .file_path = body_index_path_string.c_str(),
            .memory_address = idx_body_number.memory_file_region().data(),
            .memory_length = idx_body_number.memory_file_region().size(),
        },
    };
    SilkwormTransactionsSnapshot valid_sts{
        .segment = SilkwormMemoryMappedFile{
            .file_path = txn_segment_path_string.c_str(),
            .memory_address = txn_segment.memory_file_region().data(),
            .memory_length = txn_segment.memory_file_region().size(),
        },
        .tx_hash_index = SilkwormMemoryMappedFile{
            .file_path = tx_hash_index_path_string.c_str(),
            .memory_address = idx_txn_hash.memory_file_region().data(),
            .memory_length = idx_txn_hash.memory_file_region().size(),
        },
        .tx_hash_2_block_index = SilkwormMemoryMappedFile{
            .file_path = tx_hash2block_index_path_string.c_str(),
            .memory_address = idx_txn_hash_2_block.memory_file_region().data(),
            .memory_length = idx_txn_hash_2_block.memory_file_region().size(),
        },
    };

    SECTION("invalid handle") {
        // We purposely do not call silkworm_init to provide a null handle
        SilkwormHandle handle{nullptr};
        SilkwormChainSnapshot snapshot{valid_shs, valid_sbs, valid_sts};
        CHECK(silkworm_add_snapshot(handle, &snapshot) == SILKWORM_INVALID_HANDLE);
    }

    // Use Silkworm as a library with silkworm_init/silkworm_fini automated by RAII
    SilkwormLibrary silkworm_lib{env_path()};

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

static SilkwormRpcSettings make_rpc_settings_for_test(uint16_t api_listening_port) {
    SilkwormRpcSettings settings{
        .eth_if_log_settings = {
            .enabled = false,
            .max_file_size_mb = 1,
            .max_files = 1,
            .dump_response = false,
        },
        .eth_api_port = api_listening_port,
        .num_workers = 0,
        .erigon_json_rpc_compatibility = false,
        .ws_enabled = false,
        .ws_compression = false,
        .http_compression = false,
        // We must skip internal protocol check here (would block because gRPC server not present)
        .skip_internal_protocol_check = true,
    };
    (void)std::snprintf(settings.eth_if_log_settings.container_folder, SILKWORM_PATH_SIZE, "logs");
    (void)std::snprintf(settings.eth_api_host, SILKWORM_RPC_SETTINGS_HOST_SIZE, "localhost");
    (void)std::snprintf(settings.eth_api_spec, SILKWORM_RPC_SETTINGS_API_NAMESPACE_SPEC_SIZE, "eth,ots");
    for (auto& domain : settings.cors_domains) {
        domain[0] = '\0';
    }
    (void)std::snprintf(settings.cors_domains[0], SILKWORM_RPC_SETTINGS_CORS_DOMAIN_SIZE, "*");
    settings.jwt_file_path[0] = '\0';
    return settings;
}

static const SilkwormRpcSettings kInvalidRpcSettings{make_rpc_settings_for_test(10)};
static const SilkwormRpcSettings kValidRpcSettings{make_rpc_settings_for_test(8545)};

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_start_rpcdaemon", "[silkworm][capi]") {
    SECTION("invalid handle") {
        // We purposely do not call silkworm_init to provide a null handle
        SilkwormHandle handle{nullptr};
        CHECK(silkworm_start_rpcdaemon(handle, env, &kValidRpcSettings) == SILKWORM_INVALID_HANDLE);
    }

    // Use Silkworm as a library with silkworm_init/silkworm_fini automated by RAII
    SilkwormLibrary silkworm_lib{env_path()};

    SECTION("invalid settings") {
        CHECK(silkworm_lib.start_rpcdaemon(env, nullptr) == SILKWORM_INVALID_SETTINGS);
    }

    // The following test fails on Windows with silkworm_start_rpcdaemon returning SILKWORM_OK
#ifndef _WIN32
    SECTION("test settings: invalid port") {
        CHECK(silkworm_lib.start_rpcdaemon(env, &kInvalidRpcSettings) == SILKWORM_INTERNAL_ERROR);
    }
#endif  // _WIN32

    SECTION("test settings: valid port") {
        CHECK(silkworm_lib.start_rpcdaemon(env, &kValidRpcSettings) == SILKWORM_OK);
        REQUIRE(silkworm_lib.stop_rpcdaemon() == SILKWORM_OK);
    }
}

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_stop_rpcdaemon", "[silkworm][capi]") {
    SECTION("invalid handle") {
        // We purposely do not call silkworm_init to provide a null handle
        SilkwormHandle handle{nullptr};
        CHECK(silkworm_stop_rpcdaemon(handle) == SILKWORM_INVALID_HANDLE);
    }

    // Use Silkworm as a library with silkworm_init/silkworm_fini automated by RAII
    SilkwormLibrary silkworm_lib{env_path()};

    SECTION("not yet started") {
        CHECK(silkworm_lib.stop_rpcdaemon() == SILKWORM_OK);
    }

    SECTION("already started") {
        REQUIRE(silkworm_lib.start_rpcdaemon(env, &kValidRpcSettings) == SILKWORM_OK);
        CHECK(silkworm_lib.stop_rpcdaemon() == SILKWORM_OK);
    }
}

static SilkwormForkValidatorSettings make_fork_validator_settings_for_test() {
    SilkwormForkValidatorSettings settings{
        .batch_size = 512 * 1024 * 1024,
        .etl_buffer_size = 256 * 1024 * 1024,
        .sync_loop_throttle_seconds = 0,
        .stop_before_senders_stage = true,
    };

    return settings;
}

static const SilkwormForkValidatorSettings kValidForkValidatorSettings{make_fork_validator_settings_for_test()};

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_fork_validator", "[silkworm][capi]") {
    silkworm::test_util::SetLogVerbosityGuard log_guard(log::Level::kNone);

    // Use Silkworm as a library with silkworm_init/silkworm_fini automated by RAII
    SilkwormLibrary silkworm_lib{env_path()};

    SECTION("invalid handle") {
        // We purposely do not call silkworm_init to provide a null handle
        SilkwormHandle handle{nullptr};
        CHECK(silkworm_start_fork_validator(handle, env, &kValidForkValidatorSettings) == SILKWORM_INVALID_HANDLE);
    }

    SECTION("invalid settings") {
        CHECK(silkworm_lib.start_fork_validator(env, nullptr) == SILKWORM_INVALID_SETTINGS);
    }

    SECTION("starts fork validator with valid settings") {
        CHECK(silkworm_lib.start_fork_validator(env, &kValidForkValidatorSettings) == SILKWORM_OK);
        REQUIRE(silkworm_lib.stop_fork_validator() == SILKWORM_OK);
    }

    SECTION("validates chain") {
        silkworm_lib.start_fork_validator(env, &kValidForkValidatorSettings);

        auto const current_head_id = silkworm_lib.execution_engine().last_finalized_block();
        CHECK(current_head_id.number == 9);
        CHECK(current_head_id.hash != Hash{});
        auto const current_head = silkworm_lib.execution_engine().get_header(current_head_id.number, current_head_id.hash).value();
        auto new_block = silkworm::test_util::generate_sample_child_blocks(current_head);
        auto new_block_hash = new_block->header.hash();

        auto insert_block_success = silkworm_lib.execution_engine().insert_block(new_block);
        CHECK(insert_block_success);

        auto result = silkworm_lib.fork_validator_verify_chain(new_block_hash);
        CHECK(result == SILKWORM_OK);
    }

    SECTION("validates multiple chains") {
        silkworm_lib.start_fork_validator(env, &kValidForkValidatorSettings);

        auto const current_head_id = silkworm_lib.execution_engine().last_finalized_block();
        CHECK(current_head_id.number == 9);
        CHECK(current_head_id.hash != Hash{});
        auto const current_head = silkworm_lib.execution_engine().get_header(current_head_id.number, current_head_id.hash).value();

        auto new_block1 = silkworm::test_util::generate_sample_child_blocks(current_head);
        auto insert_block_success = silkworm_lib.execution_engine().insert_block(new_block1);
        CHECK(insert_block_success);

        auto new_block2 = silkworm::test_util::generate_sample_child_blocks(current_head);
        insert_block_success = silkworm_lib.execution_engine().insert_block(new_block2);
        CHECK(insert_block_success);

        auto result = silkworm_lib.fork_validator_verify_chain(new_block1->header.hash());
        CHECK(result == SILKWORM_OK);

        result = silkworm_lib.fork_validator_verify_chain(new_block2->header.hash());
        CHECK(result == SILKWORM_OK);
    }

    SECTION("executes fork choice update") {
        silkworm_lib.start_fork_validator(env, &kValidForkValidatorSettings);

        auto const current_head_id = silkworm_lib.execution_engine().last_finalized_block();
        auto const current_head = silkworm_lib.execution_engine().get_header(current_head_id.number, current_head_id.hash).value();
        auto new_block = silkworm::test_util::generate_sample_child_blocks(current_head);
        auto new_block_hash = new_block->header.hash();

        silkworm_lib.execution_engine().insert_block(new_block);
        silkworm_lib.fork_validator_verify_chain(new_block_hash);

        auto result = silkworm_lib.execution_engine_fork_choice_update(new_block_hash, silkworm::Hash{}, silkworm::Hash{});
        CHECK(result == SILKWORM_OK);

        auto headers = silkworm_lib.execution_engine().get_last_headers(1);
        CHECK(headers.size() == 1);
        CHECK(headers[0].hash() == new_block_hash);
    }

    SECTION("executes fork choice update with final and safe blocks") {
        silkworm_lib.start_fork_validator(env, &kValidForkValidatorSettings);

        auto const current_head_id = silkworm_lib.execution_engine().last_finalized_block();
        auto const current_head = silkworm_lib.execution_engine().get_header(current_head_id.number, current_head_id.hash).value();
        auto new_block = silkworm::test_util::generate_sample_child_blocks(current_head);
        auto new_block_hash = new_block->header.hash();

        silkworm_lib.execution_engine().insert_block(new_block);
        silkworm_lib.fork_validator_verify_chain(new_block_hash);

        auto result = silkworm_lib.execution_engine_fork_choice_update(new_block_hash, new_block_hash, new_block_hash);
        CHECK(result == SILKWORM_OK);

        auto headers = silkworm_lib.execution_engine().get_last_headers(1);
        CHECK(headers.size() == 1);
        CHECK(headers[0].hash() == new_block_hash);

        auto final_header = silkworm_lib.execution_engine().last_finalized_block();
        CHECK(final_header.number == new_block->header.number);

        auto safe_header = silkworm_lib.execution_engine().last_safe_block();
        CHECK(safe_header.number == new_block->header.number);
    }
}

}  // namespace silkworm
