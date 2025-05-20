// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "silkworm.h"

#include <cstring>

#include <catch2/catch_test_macros.hpp>
#include <evmc/evmc.h>

#include <silkworm/core/test_util/sample_blocks.hpp>
#include <silkworm/core/trie/vector_root.hpp>
#include <silkworm/db/blocks/bodies/body_index.hpp>
#include <silkworm/db/blocks/headers/header_index.hpp>
#include <silkworm/db/blocks/transactions/txn_index.hpp>
#include <silkworm/db/blocks/transactions/txn_to_block_index.hpp>
#include <silkworm/db/datastore/kvdb/mdbx.hpp>
#include <silkworm/db/datastore/snapshots/schema.hpp>
#include <silkworm/db/datastore/snapshots/segment/segment_reader.hpp>
#include <silkworm/db/state/step_txn_id_converter.hpp>
#include <silkworm/db/test_util/temp_snapshots.hpp>
#include <silkworm/db/test_util/test_database_context.hpp>
#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/common/environment.hpp>

#include "instance.hpp"

namespace silkworm {

namespace snapshot_test = snapshots::test_util;
using namespace silkworm::db;
using namespace silkworm::datastore::kvdb;

struct CApiTest {
    TemporaryDirectory tmp_dir;
    db::test_util::TestDatabaseContext database{tmp_dir};

    SilkwormSettings settings{.log_verbosity = SilkwormLogLevel::SILKWORM_LOG_NONE};
    mdbx::env env{*database.chaindata_rw()};
    const std::filesystem::path& env_path() const { return database.chaindata_dir_path(); }
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

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_libmdbx_version: OK", "[capi]") {
    CHECK(std::strcmp(silkworm_libmdbx_version(), ::mdbx::get_version().git.describe) == 0);
}

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_init: empty settings", "[capi]") {
    SilkwormHandle handle{nullptr};
    CHECK(silkworm_init(&handle, &settings) == SILKWORM_INVALID_PATH);
    CHECK(!handle);
}

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_init: empty data folder path", "[capi]") {
    copy_path(settings.data_dir_path, "");
    copy_git_version(settings.libmdbx_version, silkworm_libmdbx_version());
    SilkwormHandle handle{nullptr};
    CHECK(silkworm_init(&handle, &settings) == SILKWORM_INVALID_PATH);
    CHECK(!handle);
}

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_init: empty MDBX version", "[capi]") {
    copy_path(settings.data_dir_path, env_path().string().c_str());
    copy_git_version(settings.libmdbx_version, "");
    SilkwormHandle handle{nullptr};
    CHECK(silkworm_init(&handle, &settings) == SILKWORM_INCOMPATIBLE_LIBMDBX);
    CHECK(!handle);
}

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_init: incompatible MDBX version", "[capi]") {
    copy_path(settings.data_dir_path, env_path().string().c_str());
    copy_git_version(settings.libmdbx_version, "v0.1.0");
    SilkwormHandle handle{nullptr};
    CHECK(silkworm_init(&handle, &settings) == SILKWORM_INCOMPATIBLE_LIBMDBX);
    CHECK(!handle);
}

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_init: OK", "[capi]") {
    copy_path(settings.data_dir_path, env_path().string().c_str());
    copy_git_version(settings.libmdbx_version, silkworm_libmdbx_version());
    SilkwormHandle handle{nullptr};
    CHECK(silkworm_init(&handle, &settings) == SILKWORM_OK);
    CHECK(handle);
    CHECK(silkworm_fini(handle) == SILKWORM_OK);
}

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_fini: not initialized", "[capi]") {
    SilkwormHandle handle{nullptr};
    CHECK(silkworm_fini(handle) == SILKWORM_INVALID_HANDLE);
}

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_fini: OK", "[capi]") {
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

    int execute_txn(MDBX_txn* tx, uint64_t block_num, silkworm::Hash head_hash, uint64_t txn_index, uint64_t txn_id) const {
        SilkwormBytes32 head_hash_bytes{};
        std::memcpy(head_hash_bytes.bytes, head_hash.bytes, 32);

        return silkworm_execute_txn(handle_, tx, block_num, head_hash_bytes, txn_index, txn_id, nullptr, nullptr);
    }

    int add_blocks_snapshot_bundle(SilkwormBlocksSnapshotBundle* bundle) const {
        return silkworm_add_blocks_snapshot_bundle(handle_, bundle);
    }

    int add_state_snapshot_bundle_latest(SilkwormStateSnapshotBundleLatest* bundle) const {
        return silkworm_add_state_snapshot_bundle_latest(handle_, bundle);
    }

    int add_state_snapshot_bundle_historical(SilkwormStateSnapshotBundleHistorical* bundle) const {
        return silkworm_add_state_snapshot_bundle_historical(handle_, bundle);
    }

    int start_rpcdaemon(MDBX_env* env, const SilkwormRpcSettings* settings) const {
        return silkworm_start_rpcdaemon(handle_, env, settings);
    }

    int stop_rpcdaemon() const {
        return silkworm_stop_rpcdaemon(handle_);
    }

  private:
    SilkwormHandle handle_{nullptr};
};

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_execute_blocks_ephemeral: block not found", "[capi]") {
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

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_execute_blocks_perpetual: block not found", "[capi]") {
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

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_execute_blocks_ephemeral: chain id not found", "[capi]") {
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

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_execute_blocks_perpetual: chain id not found", "[capi]") {
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

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_execute_blocks_ephemeral single block: OK", "[capi]") {
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

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_execute_blocks_perpetual single block: OK", "[capi]") {
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

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_execute_blocks_ephemeral multiple blocks: OK", "[capi]") {
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

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_execute_blocks_perpetual multiple blocks: OK", "[capi]") {
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

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_execute_blocks_ephemeral multiple blocks: insufficient buffer", "[capi]") {
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

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_execute_blocks_perpetual multiple blocks: insufficient buffer", "[capi]") {
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

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_add_blocks_snapshot_bundle", "[capi]") {
    static constexpr datastore::StepToTimestampConverter kStepConverter = db::blocks::kStepToBlockNumConverter;

    snapshot_test::SampleHeaderSnapshotFile header_segment_file{tmp_dir.path()};
    auto& header_segment_path = header_segment_file.path();
    snapshot_test::SampleBodySnapshotFile body_segment_file{tmp_dir.path()};
    auto& body_segment_path = body_segment_file.path();
    snapshot_test::SampleTransactionSnapshotFile txn_segment_file{tmp_dir.path()};
    auto& txn_segment_path = txn_segment_file.path();

    auto header_index_builder = snapshots::HeaderIndex::make(header_segment_path);
    header_index_builder.set_base_data_id(header_segment_file.block_num_range().start);
    REQUIRE_NOTHROW(header_index_builder.build());
    snapshots::segment::SegmentFileReader header_segment{header_segment_path, kStepConverter};
    snapshots::rec_split::AccessorIndex idx_header_hash{header_segment_path.related_path_ext(db::blocks::kIdxExtension)};

    auto body_index_builder = snapshots::BodyIndex::make(body_segment_path);
    body_index_builder.set_base_data_id(body_segment_file.block_num_range().start);
    REQUIRE_NOTHROW(body_index_builder.build());
    snapshots::segment::SegmentFileReader body_segment{body_segment_path, kStepConverter};
    snapshots::rec_split::AccessorIndex idx_body_number{body_segment_path.related_path_ext(db::blocks::kIdxExtension)};

    auto tx_index_builder = snapshots::TransactionIndex::make(body_segment_path, txn_segment_path);
    tx_index_builder.build();
    auto tx_index_hash_to_block_builder = snapshots::TransactionToBlockIndex::make(body_segment_path, txn_segment_path, txn_segment_file.block_num_range().start);
    tx_index_hash_to_block_builder.build();
    snapshots::segment::SegmentFileReader txn_segment{txn_segment_path, kStepConverter};
    snapshots::rec_split::AccessorIndex idx_txn_hash{txn_segment_path.related_path_ext(db::blocks::kIdxExtension)};
    snapshots::rec_split::AccessorIndex idx_txn_hash_2_block{tx_index_hash_to_block_builder.path()};

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
        SilkwormBlocksSnapshotBundle bundle{valid_shs, valid_sbs, valid_sts};
        CHECK(silkworm_add_blocks_snapshot_bundle(handle, &bundle) == SILKWORM_INVALID_HANDLE);
    }

    // Use Silkworm as a library with silkworm_init/silkworm_fini automated by RAII
    SilkwormLibrary silkworm_lib{env_path()};

    SECTION("invalid header segment path") {
        SilkwormHeadersSnapshot invalid_shs{valid_shs};
        invalid_shs.segment.file_path = nullptr;  // as if left unassigned, i.e. empty
        SilkwormBlocksSnapshotBundle bundle{invalid_shs, valid_sbs, valid_sts};
        const int result{silkworm_lib.add_blocks_snapshot_bundle(&bundle)};
        CHECK(result == SILKWORM_INVALID_PATH);
    }
    SECTION("invalid header index path") {
        SilkwormHeadersSnapshot invalid_shs{valid_shs};
        invalid_shs.header_hash_index.file_path = nullptr;  // as if left unassigned, i.e. empty
        SilkwormBlocksSnapshotBundle bundle{invalid_shs, valid_sbs, valid_sts};
        const int result{silkworm_lib.add_blocks_snapshot_bundle(&bundle)};
        CHECK(result == SILKWORM_INVALID_PATH);
    }
    SECTION("invalid body segment path") {
        SilkwormBodiesSnapshot invalid_sbs{valid_sbs};
        invalid_sbs.segment.file_path = nullptr;  // as if left unassigned, i.e. empty
        SilkwormBlocksSnapshotBundle bundle{valid_shs, invalid_sbs, valid_sts};
        const int result{silkworm_lib.add_blocks_snapshot_bundle(&bundle)};
        CHECK(result == SILKWORM_INVALID_PATH);
    }
    SECTION("invalid body index path") {
        SilkwormBodiesSnapshot invalid_sbs{valid_sbs};
        invalid_sbs.block_num_index.file_path = nullptr;  // as if left unassigned, i.e. empty
        SilkwormBlocksSnapshotBundle bundle{valid_shs, invalid_sbs, valid_sts};
        const int result{silkworm_lib.add_blocks_snapshot_bundle(&bundle)};
        CHECK(result == SILKWORM_INVALID_PATH);
    }
    SECTION("invalid transaction segment path") {
        SilkwormTransactionsSnapshot invalid_sts{valid_sts};
        invalid_sts.segment.file_path = nullptr;  // as if left unassigned, i.e. empty
        SilkwormBlocksSnapshotBundle bundle{valid_shs, valid_sbs, invalid_sts};
        const int result{silkworm_lib.add_blocks_snapshot_bundle(&bundle)};
        CHECK(result == SILKWORM_INVALID_PATH);
    }
    SECTION("invalid transaction hash index path") {
        SilkwormTransactionsSnapshot invalid_sts{valid_sts};
        invalid_sts.tx_hash_index.file_path = nullptr;  // as if left unassigned, i.e. empty
        SilkwormBlocksSnapshotBundle bundle{valid_shs, valid_sbs, invalid_sts};
        const int result{silkworm_lib.add_blocks_snapshot_bundle(&bundle)};
        CHECK(result == SILKWORM_INVALID_PATH);
    }
    SECTION("invalid transaction hash2block index path") {
        SilkwormTransactionsSnapshot invalid_sts{valid_sts};
        invalid_sts.tx_hash_2_block_index.file_path = nullptr;  // as if left unassigned, i.e. empty
        SilkwormBlocksSnapshotBundle bundle{valid_shs, valid_sbs, invalid_sts};
        const int result{silkworm_lib.add_blocks_snapshot_bundle(&bundle)};
        CHECK(result == SILKWORM_INVALID_PATH);
    }
    SECTION("invalid empty chain snapshot") {
        SilkwormBlocksSnapshotBundle bundle{};
        const int result{silkworm_lib.add_blocks_snapshot_bundle(&bundle)};
        CHECK(result == SILKWORM_INVALID_PATH);
    }
    SECTION("valid") {
        SilkwormBlocksSnapshotBundle bundle{valid_shs, valid_sbs, valid_sts};
        const int result{silkworm_lib.add_blocks_snapshot_bundle(&bundle)};
        CHECK(result == SILKWORM_OK);
    }
}

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_add_state_snapshot", "[capi]") {
    using snapshots::Schema;
    using namespace snapshots;
    constexpr uint32_t kZeroSalt{0};

    const snapshot_test::SampleAccountsDomainSegmentFile kv_segment_file{tmp_dir.path()};
    segment::KVSegmentFileReader kv_segment{kv_segment_file.path(), db::state::kStepToTxnIdConverter, seg::CompressionKind::kAll};
    const auto kv_segment_path_string{kv_segment_file.path().path().string()};

    const snapshot_test::SampleAccountsDomainExistenceIndexFile existence_index_file{tmp_dir.path()};
    bloom_filter::BloomFilter existence_index{existence_index_file.path().path(), KeyHasher{kZeroSalt}};
    const auto existence_index_path_string{existence_index_file.path().path().string()};

    const snapshot_test::SampleAccountsDomainBTreeIndexFile btree_index_file{tmp_dir.path()};
    btree::BTreeIndex btree_index{btree_index_file.path().path()};
    const auto btree_index_path_string{btree_index_file.path().path().string()};

    [[maybe_unused]] snapshots::Domain domain{
        .kv_segment = kv_segment,
        .existence_index = existence_index,
        .btree_index = btree_index,
    };

    // Prepare templates for C data structures of valid state (D/H/II) snapshots
    SilkwormDomainSnapshot sample_domain_snapshot{
        .segment = SilkwormMemoryMappedFile{
            .file_path = kv_segment_path_string.c_str(),
            .memory_address = kv_segment.memory_file_region().data(),
            .memory_length = kv_segment.memory_file_region().size(),
        },
        .existence_index = SilkwormMemoryMappedFile{
            .file_path = existence_index_path_string.c_str(),
            .memory_address = nullptr,  // bloom filter is fully kept in memory, no mmap
            .memory_length = 0,
        },
        .btree_index = SilkwormMemoryMappedFile{
            .file_path = btree_index_path_string.c_str(),
            .memory_address = btree_index.memory_file_region().data(),
            .memory_length = btree_index.memory_file_region().size(),
        },
        .has_accessor_index = false,
    };

    SilkwormDomainSnapshot valid_accounts_ds{sample_domain_snapshot};
    SilkwormDomainSnapshot valid_storage_ds{sample_domain_snapshot};
    SilkwormDomainSnapshot valid_code_ds{sample_domain_snapshot};
    SilkwormDomainSnapshot valid_commitment_ds{sample_domain_snapshot};
    SilkwormDomainSnapshot valid_receipts_ds{sample_domain_snapshot};

    SilkwormStateSnapshotBundleLatest valid_bundle_latest{
        .accounts = valid_accounts_ds,
        .storage = valid_storage_ds,
        .code = valid_code_ds,
        .commitment = valid_commitment_ds,
        .receipts = valid_receipts_ds,
    };

    SECTION("invalid handle") {
        // We purposely do not call silkworm_init to provide a null handle
        SilkwormHandle handle{nullptr};
        CHECK(silkworm_add_state_snapshot_bundle_latest(handle, &valid_bundle_latest) == SILKWORM_INVALID_HANDLE);
    }

    // Use Silkworm as a library with silkworm_init/silkworm_fini automated by RAII
    SilkwormLibrary silkworm_lib{env_path()};

    SECTION("invalid accounts segment path") {
        SilkwormStateSnapshotBundleLatest invalid_bundle{valid_bundle_latest};
        invalid_bundle.accounts.segment.file_path = nullptr;  // as if left unassigned, i.e. empty
        const int result = silkworm_lib.add_state_snapshot_bundle_latest(&invalid_bundle);
        CHECK(result == SILKWORM_INVALID_PATH);
    }
    SECTION("invalid storage segment path") {
        SilkwormStateSnapshotBundleLatest invalid_bundle{valid_bundle_latest};
        invalid_bundle.storage.segment.file_path = nullptr;  // as if left unassigned, i.e. empty
        const int result = silkworm_lib.add_state_snapshot_bundle_latest(&invalid_bundle);
        CHECK(result == SILKWORM_INVALID_PATH);
    }
    SECTION("invalid code segment path") {
        SilkwormStateSnapshotBundleLatest invalid_bundle{valid_bundle_latest};
        invalid_bundle.code.segment.file_path = nullptr;  // as if left unassigned, i.e. empty
        const int result = silkworm_lib.add_state_snapshot_bundle_latest(&invalid_bundle);
        CHECK(result == SILKWORM_INVALID_PATH);
    }
    // TODO(canepat): enable after fixing .kvi configuration with IndexList-like implementation
    /*SECTION("invalid commitment segment path") {
        SilkwormStateSnapshotBundleLatest invalid_bundle{valid_bundle_latest};
        invalid_bundle.commitment.segment.file_path = nullptr;  // as if left unassigned, i.e. empty
        const int result = silkworm_lib.add_state_snapshot_bundle_latest(&invalid_bundle);
        CHECK(result == SILKWORM_INVALID_PATH);
    }*/
    SECTION("invalid receipts segment path") {
        SilkwormStateSnapshotBundleLatest invalid_bundle{valid_bundle_latest};
        invalid_bundle.receipts.segment.file_path = nullptr;  // as if left unassigned, i.e. empty
        const int result = silkworm_lib.add_state_snapshot_bundle_latest(&invalid_bundle);
        CHECK(result == SILKWORM_INVALID_PATH);
    }
    SECTION("invalid empty state snapshot") {
        SilkwormStateSnapshotBundleLatest invalid_bundle{};
        const int result{silkworm_lib.add_state_snapshot_bundle_latest(&invalid_bundle)};
        CHECK(result == SILKWORM_INVALID_PATH);
    }
    SECTION("valid latest") {
        const int result = silkworm_lib.add_state_snapshot_bundle_latest(&valid_bundle_latest);
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

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_start_rpcdaemon", "[capi]") {
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

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_stop_rpcdaemon", "[capi]") {
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

TEST_CASE_METHOD(CApiTest, "CAPI silkworm_txn: single", "[silkworm][capi]") {
    // Use Silkworm as a library with silkworm_init/silkworm_fini automated by RAII
    SilkwormLibrary silkworm_lib{env_path()};

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

    RWTxnManaged external_txn{env};
    auto result = silkworm_lib.execute_txn(*external_txn, 10, block.header.hash(), 0, 9);
    CHECK(result == SILKWORM_INVALID_BLOCK);
    CHECK_NOTHROW(external_txn.abort());
}

/*
    The following test is disabled because it requires a database with a chain of blocks to be executed.
    It is not possible to create such a database in a test environment, still it is very usefull to run tests locally.

    TODO: Remove the test after CAPI silkworm_txn is fully tested
*/
// TEST_CASE("CAPI silkworm_txn: single", "[silkworm][capi]") {
//     auto data_dir = DataDirectory{"/path/to/data"};
//     SilkwormLibrary silkworm_lib{data_dir.path()};

//     silkworm::datastore::kvdb::EnvConfig env_config{
//         .path = data_dir.chaindata().path().string(),
//         .create = false,
//         .exclusive = true,
//         .in_memory = false,
//         .shared = false,
//     };
//     auto env = open_env(env_config);

//     silkworm::datastore::kvdb::RWAccess rwa{env};
//     auto tx = rwa.start_rw_tx();

//     silkworm_lib.execute_txn(*tx, 7763755, silkworm::Hash{0xa96a1cdc01a6b9f502d0005a60d0c99eaa3b552699f1a71c0112d3f057b874d7_bytes32}, 112, 439062500);
//     silkworm_lib.execute_txn(*tx, 7763755, silkworm::Hash{0xa96a1cdc01a6b9f502d0005a60d0c99eaa3b552699f1a71c0112d3f057b874d7_bytes32}, 113, 439062501);
//     tx.abort();
// }

}  // namespace silkworm
