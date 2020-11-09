/*
   Copyright 2020 The Silkworm Authors

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

#include <CLI/CLI.hpp>
#include <boost/endian/conversion.hpp>
#include <gsl/gsl_util>
#include <iostream>
#include <limits>
#include <stdexcept>

#include "tg_api/silkworm_tg_api.h"

static constexpr const char* kMigrationsTable{"migrations"};
static constexpr const char* kDatabaseInfoTable{"DBINFO"};
static constexpr const char* kSyncStageProgressTable{"SSP2"};
static constexpr const char* kExecutionStage{"Execution"};
static constexpr const char* kStorageModeReceipts{"smReceipts"};

static inline void check_lmdb_err(int err) {
    if (err != MDB_SUCCESS) {
        throw std::runtime_error(mdb_strerror(err));
    }
}

static uint64_t already_executed_block(MDB_txn* txn) {
    MDB_dbi dbi;
    check_lmdb_err(mdb_dbi_open(txn, kSyncStageProgressTable, /*flags=*/0, &dbi));
    MDB_val key;
    key.mv_size = std::strlen(kExecutionStage);
    key.mv_data = const_cast<char*>(kExecutionStage);
    MDB_val data;
    int status{mdb_get(txn, dbi, &key, &data)};
    if (status == MDB_NOTFOUND) {
        return 0;
    }
    check_lmdb_err(status);
    return boost::endian::load_big_u64(static_cast<uint8_t*>(data.mv_data));
}

static void save_progress(MDB_txn* txn, uint64_t block_number) {
    MDB_dbi dbi;
    check_lmdb_err(mdb_dbi_open(txn, kSyncStageProgressTable, /*flags=*/0, &dbi));
    MDB_val key;
    key.mv_size = std::strlen(kExecutionStage);
    key.mv_data = const_cast<char*>(kExecutionStage);
    MDB_val data;
    uint8_t val[8];
    boost::endian::store_big_u64(&val[0], block_number);
    data.mv_size = 8;
    data.mv_data = &val[0];
    check_lmdb_err(mdb_put(txn, dbi, &key, &data, /*flags=*/0));
}

static bool migration_happened(MDB_txn* txn, const char* name) {
    MDB_dbi dbi;
    check_lmdb_err(mdb_dbi_open(txn, kMigrationsTable, /*flags=*/0, &dbi));
    MDB_val key;
    key.mv_size = std::strlen(name);
    key.mv_data = const_cast<char*>(name);
    MDB_val data;
    int status{mdb_get(txn, dbi, &key, &data)};
    if (status == MDB_NOTFOUND) {
        return false;
    }
    check_lmdb_err(status);
    return true;
}

static bool storage_mode_has_write_receipts(MDB_txn* txn) {
    MDB_dbi dbi;
    check_lmdb_err(mdb_dbi_open(txn, kDatabaseInfoTable, /*flags=*/0, &dbi));
    MDB_val key;
    key.mv_size = std::strlen(kStorageModeReceipts);
    key.mv_data = const_cast<char*>(kStorageModeReceipts);
    MDB_val data;
    int status{mdb_get(txn, dbi, &key, &data)};
    if (status == MDB_NOTFOUND) {
        return false;
    }
    check_lmdb_err(status);
    if (data.mv_size != 1) {
        return false;
    }
    const auto ptr{static_cast<uint8_t*>(data.mv_data)};
    return *ptr == 1;
}

int main(int argc, char* argv[]) {
    CLI::App app{"Execute Ethereum blocks and write the result into the DB"};

    std::string db_path{};
    app.add_option("-d,--datadir", db_path, "Path to a database populated by Turbo-Geth")
        ->required()
        ->check(CLI::ExistingDirectory);

    uint64_t to_block{std::numeric_limits<uint64_t>::max()};
    app.add_option("--to", to_block, "Block execute up to", true);

    uint64_t batch_mib{512};
    app.add_option("--batch_mib", batch_mib, "Batch size in mebibytes of DB changes to accumulate before committing", true);

    CLI11_PARSE(app, argc, argv);

    std::clog << "Starting block execution. DB: " << db_path << std::endl;

    MDB_env* env{nullptr};
    check_lmdb_err(mdb_env_create(&env));
    auto cleanup{gsl::finally([env] { mdb_env_close(env); })};

    check_lmdb_err(mdb_env_set_mapsize(env, 1ull << 40));
    check_lmdb_err(mdb_env_set_maxdbs(env, 128));
    check_lmdb_err(mdb_env_open(env, db_path.c_str(), MDB_NOTLS | MDB_NORDAHEAD | MDB_NOSYNC, 0644));

    MDB_txn* txn{nullptr};
    check_lmdb_err(mdb_txn_begin(env, /*parent=*/nullptr, /*flags=*/0, &txn));

    bool write_receipts{storage_mode_has_write_receipts(txn)};
    if (write_receipts && (!migration_happened(txn, "receipts_cbor_encode") ||
                           !migration_happened(txn, "receipts_store_logs_separately"))) {
        std::clog << "Legacy stored receipts are not supported\n";
        return -2;
    }

    uint64_t batch_size{batch_mib * 1024 * 1024};

    uint64_t previous_progress{already_executed_block(txn)};
    uint64_t current_progress{previous_progress};

    for (uint64_t block_number{previous_progress + 1}; block_number <= to_block; ++block_number) {
        int lmdb_error_code{MDB_SUCCESS};
        SilkwormStatusCode status{silkworm_execute_blocks(txn, /*chain_id=*/1, block_number, to_block, batch_size,
                                                          write_receipts, &current_progress, &lmdb_error_code)};
        if (status != kSilkwormSuccess && status != kSilkwormBlockNotFound) {
            std::clog << "Error in silkworm_execute_blocks: " << status << ", LMDB: " << lmdb_error_code << std::endl;
            return status;
        }

        block_number = current_progress;

        save_progress(txn, current_progress);
        check_lmdb_err(mdb_txn_commit(txn));

        if (status == kSilkwormBlockNotFound) {
            break;
        }

        std::clog << "Blocks <= " << current_progress << " committed" << std::endl;

        check_lmdb_err(mdb_txn_begin(env, /*parent=*/nullptr, /*flags=*/0, &txn));
    }

    if (current_progress > previous_progress) {
        std::clog << "All blocks <= " << current_progress << " executed and committed" << std::endl;
    } else {
        std::clog << "Nothing to execute" << std::endl;
    }

    return 0;
}
