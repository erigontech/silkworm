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
#include <limits>
#include <silkworm/common/log.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/execution/execution.hpp>

#include "tg_api/silkworm_tg_api.h"

static constexpr const char* kExecutionStageKey{"Execution"};

using namespace silkworm;

static uint64_t already_executed_block(lmdb::Transaction& txn) {
    auto tbl{txn.open(db::table::kSyncStageProgress)};
    std::optional<ByteView> data{tbl->get(byte_view_of_c_str(kExecutionStageKey))};
    if (data) {
        return boost::endian::load_big_u64(data->data());
    } else {
        return 0;
    }
}

static void save_progress(lmdb::Transaction& txn, uint64_t block_number) {
    auto tbl{txn.open(db::table::kSyncStageProgress)};
    Bytes val(8, '\0');
    boost::endian::store_big_u64(&val[0], block_number);
    tbl->put(byte_view_of_c_str(kExecutionStageKey), val);
}

static bool migration_happened(lmdb::Transaction& txn, const char* name) {
    auto tbl{txn.open(db::table::kMigrations)};
    return tbl->get(byte_view_of_c_str(name)).has_value();
}

int main(int argc, char* argv[]) {
    CLI::App app{"Execute Ethereum blocks and write the result into the DB"};

    std::string db_path{db::default_path()};
    app.add_option("-d,--datadir", db_path, "Path to a database populated by Turbo-Geth", true)
        ->check(CLI::ExistingDirectory);

    std::string map_size_str;
    CLI::Option* map_size_opt{app.add_option("--lmdb.mapSize", map_size_str, "Lmdb map size")};

    uint64_t to_block{std::numeric_limits<uint64_t>::max()};
    app.add_option("--to", to_block, "Block execute up to");

    std::string batch_size_str{"512MB"};
    app.add_option("--batch", batch_size_str, "Batch size of DB changes to accumulate before committing", true);

    CLI11_PARSE(app, argc, argv);

    Logger::default_logger().set_local_timezone(true);  // for compatibility with TG logging

    // Check data.mdb exists in provided directory
    boost::filesystem::path db_file{boost::filesystem::path(db_path) / boost::filesystem::path("data.mdb")};
    if (!boost::filesystem::exists(db_file)) {
        SILKWORM_LOG(LogError) << "Can't find a valid TG data file in " << db_path << std::endl;
        return -1;
    }

    std::optional<size_t> map_size{std::nullopt};
    if (*map_size_opt) {
        // Check provided map size is valid
        map_size = parse_size(map_size_str);
        if (!map_size.has_value()) {
            SILKWORM_LOG(LogError) << "Invalid --lmdb.mapSize value provided : " << map_size_str << std::endl;
            return -2;
        }
    }

    auto batch_size{parse_size(batch_size_str)};
    if (!batch_size.has_value()) {
        SILKWORM_LOG(LogError) << "Invalid --batch value provided : " << batch_size_str << std::endl;
        return -3;
    }

    SILKWORM_LOG(LogInfo) << "Starting block execution. DB: " << db_file << std::endl;

    try {
        lmdb::DatabaseConfig db_config{db_path};
        if (map_size) {
            db_config.map_size = *map_size;
        }
        db_config.set_readonly(false);
        std::shared_ptr<lmdb::Environment> env{lmdb::get_env(db_config)};
        std::unique_ptr<lmdb::Transaction> txn{env->begin_rw_transaction()};

        bool write_receipts{db::read_storage_mode_receipts(*txn)};
        if (write_receipts && (!migration_happened(*txn, "receipts_cbor_encode") ||
                               !migration_happened(*txn, "receipts_store_logs_separately"))) {
            SILKWORM_LOG(LogError) << "Legacy stored receipts are not supported" << std::endl;
            return -4;
        }

        uint64_t previous_progress{already_executed_block(*txn)};
        uint64_t current_progress{previous_progress};

        for (uint64_t block_number{previous_progress + 1}; block_number <= to_block; ++block_number) {
            int lmdb_error_code{MDB_SUCCESS};
            SilkwormStatusCode status{silkworm_execute_blocks(*txn->handle(), /*chain_id=*/1, block_number, to_block,
                                                              *batch_size, write_receipts, &current_progress,
                                                              &lmdb_error_code)};
            if (status != kSilkwormSuccess && status != kSilkwormBlockNotFound) {
                SILKWORM_LOG(LogError) << "Error in silkworm_execute_blocks: " << status
                                       << ", LMDB: " << lmdb_error_code << std::endl;
                return status;
            }

            block_number = current_progress;

            save_progress(*txn, current_progress);
            lmdb::err_handler(txn->commit());
            txn.reset();

            if (status == kSilkwormBlockNotFound) {
                break;
            }

            SILKWORM_LOG(LogInfo) << "Blocks <= " << current_progress << " committed" << std::endl;
            txn = env->begin_rw_transaction();
        }

        if (current_progress > previous_progress) {
            SILKWORM_LOG(LogInfo) << "All blocks <= " << current_progress << " executed and committed" << std::endl;
        } else {
            SILKWORM_LOG(LogWarn) << "Nothing to execute" << std::endl;
        }

    } catch (const std::exception& ex) {
        SILKWORM_LOG(LogError) << ex.what() << std::endl;
        return -5;
    }

    return 0;
}
