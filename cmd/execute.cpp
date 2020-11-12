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
#include <iostream>
#include <limits>
#include <silkworm/db/chaindb.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/db/util.hpp>
#include <stdexcept>

#include "tg_api/silkworm_tg_api.h"

static constexpr const char* kExecutionStageKey{"Execution"};
static constexpr const char* kStorageModeReceiptsKey{"smReceipts"};

static uint64_t already_executed_block(std::unique_ptr<silkworm::lmdb::Transaction>& txn) {
    auto tbl = txn->open(silkworm::db::table::kSyncStageProgress);
    MDB_val key, data;
    key.mv_size = std::strlen(kExecutionStageKey);
    key.mv_data = (void*)kExecutionStageKey;
    int rc{tbl->seek_exact(&key, &data)};
    switch (rc) {
        case MDB_NOTFOUND:
            return 0;
        case MDB_SUCCESS:
            break;
        default:
            silkworm::lmdb::err_handler(rc);
    }

    return boost::endian::load_big_u64(static_cast<uint8_t*>(data.mv_data));
}

static void save_progress(std::unique_ptr<silkworm::lmdb::Transaction>& txn, uint64_t block_number) {
    auto tbl = txn->open(silkworm::db::table::kSyncStageProgress);
    MDB_val key, data;
    key.mv_size = std::strlen(kExecutionStageKey);
    key.mv_data = (void*)kExecutionStageKey;

    uint8_t val[8];
    boost::endian::store_big_u64(&val[0], block_number);
    data.mv_size = 8;
    data.mv_data = &val[0];

    silkworm::lmdb::err_handler(tbl->put(&key, &data, /*flags=*/0));
}

static bool migration_happened(std::unique_ptr<silkworm::lmdb::Transaction>& txn, const char* migration_name) {
    auto tbl = txn->open(silkworm::db::table::kMigrations);
    MDB_val key, data;
    key.mv_size = std::strlen(migration_name);
    key.mv_data = (void*)migration_name;
    int rc{tbl->seek_exact(&key, &data)};
    switch (rc) {
        case MDB_NOTFOUND:
            return false;
        case MDB_SUCCESS:
            break;
        default:
            silkworm::lmdb::err_handler(rc);
    }
    return true;
}

static bool storage_mode_has_write_receipts(std::unique_ptr<silkworm::lmdb::Transaction>& txn) {
    auto tbl = txn->open(silkworm::db::table::kDatabaseInfo);
    MDB_val key, data;
    key.mv_size = std::strlen(kStorageModeReceiptsKey);
    key.mv_data = (void*)kStorageModeReceiptsKey;
    int rc{tbl->seek_exact(&key, &data)};
    switch (rc) {
        case MDB_NOTFOUND:
            return false;
        case MDB_SUCCESS:
            break;
        default:
            silkworm::lmdb::err_handler(rc);
    }

    if (data.mv_size == 1 && *(static_cast<uint8_t*>(data.mv_data)) == 1) {
        return true;
    }
    return false;
}

int main(int argc, char* argv[]) {
    CLI::App app{"Execute Ethereum blocks and write the result into the DB"};

    std::string db_path{silkworm::db::default_path()};
    app.add_option("-d,--datadir", db_path, "Path to a database populated by Turbo-Geth", true)
        ->required()
        ->check(CLI::ExistingDirectory);

    std::string map_size_str{"1TB"};
    app.add_option("--lmdb.mapSize", map_size_str, "Lmdb map size", true);

    uint64_t to_block{std::numeric_limits<uint64_t>::max()};
    app.add_option("--to", to_block, "Block execute up to");

    uint64_t batch_mib{512};
    app.add_option("--batch_mib", batch_mib, "Batch size in mebibytes of DB changes to accumulate before committing",
                   true);

    CLI11_PARSE(app, argc, argv);

    // Check data.mdb exists in provided directory
    boost::filesystem::path db_file{boost::filesystem::path(db_path) / boost::filesystem::path("data.mdb")};
    if (!boost::filesystem::exists(db_file)) {
        std::clog << "Can't find a valid TG data file in " << db_path << std::endl;
        return -2;
    }

    // Check provided map size is valid
    auto map_size{silkworm::parse_size(map_size_str)};
    if (!map_size.has_value()) {
        std::clog << "Invalid --lmdb.mapSize value provided : " << map_size_str << std::endl;
        return -2;
    }

    std::clog << "Starting block execution. DB: " << db_file << std::endl;

    silkworm::lmdb::DatabaseConfig db_config{db_path, *map_size};
    db_config.set_readonly(false);
    std::shared_ptr<silkworm::lmdb::Environment> env{nullptr};
    std::unique_ptr<silkworm::lmdb::Transaction> txn{nullptr};

    try {
        env = silkworm::lmdb::get_env(db_config);
        txn = env->begin_rw_transaction();
        bool write_receipts{storage_mode_has_write_receipts(txn)};
        if (write_receipts && (!migration_happened(txn, "receipts_cbor_encode") ||
                               !migration_happened(txn, "receipts_store_logs_separately"))) {
            std::clog << "Legacy stored receipts are not supported" << std::endl;
            return -1;
        }

        uint64_t batch_size{batch_mib * 1024 * 1024};
        uint64_t previous_progress{already_executed_block(txn)};
        uint64_t current_progress{previous_progress};

        for (uint64_t block_number{previous_progress + 1}; block_number <= to_block; ++block_number) {
            int lmdb_error_code{MDB_SUCCESS};
            SilkwormStatusCode status{silkworm_execute_blocks(*txn->handle(), /*chain_id=*/1, block_number, to_block,
                                                              batch_size, write_receipts, &current_progress,
                                                              &lmdb_error_code)};
            if (status != kSilkwormSuccess && status != kSilkwormBlockNotFound) {
                std::clog << "Error in silkworm_execute_blocks: " << status << ", LMDB: " << lmdb_error_code
                          << std::endl;
                return status;
            }

            block_number = current_progress;

            save_progress(txn, current_progress);
            silkworm::lmdb::err_handler(txn->commit());
            txn.reset();

            if (status == kSilkwormBlockNotFound) {
                break;
            }

            std::clog << "Blocks <= " << current_progress << " committed" << std::endl;
            txn = env->begin_rw_transaction();
        }

        if (current_progress > previous_progress) {
            std::clog << "All blocks <= " << current_progress << " executed and committed" << std::endl;
        } else {
            std::clog << "Nothing to execute" << std::endl;
        }

    } catch (const std::logic_error& ex) {
        std::clog << "Error : " << ex.what() << std::endl;
        return -2;
    } catch (const std::exception& ex) {
        std::clog << "Unexpected error : " << ex.what() << std::endl;
        return -2;
    }

    return 0;
}
