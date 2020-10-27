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
#include <boost/log/trivial.hpp>
#include <limits>
#include <memory>
#include <optional>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/execution/execution.hpp>

using namespace silkworm;

static constexpr const char* kExecutionStage{"Execution"};

static uint64_t already_executed_block(lmdb::Transaction& txn) {
    std::unique_ptr<lmdb::Table> progress_table{txn.open(db::table::kSyncStageProgress)};
    ByteView stage_key{byte_view_of_c_str(kExecutionStage)};
    std::optional<ByteView> already_executed{progress_table->get(stage_key)};
    if (already_executed) {
        return boost::endian::load_big_u64(already_executed->data());
    } else {
        return 0;
    }
}

static void save_progress(lmdb::Transaction& txn, uint64_t block_number) {
    std::unique_ptr<lmdb::Table> progress_table{txn.open(db::table::kSyncStageProgress)};
    ByteView stage_key{byte_view_of_c_str(kExecutionStage)};
    Bytes val(8, '\0');
    boost::endian::store_big_u64(&val[0], block_number);
    progress_table->put(stage_key, val);
}

static bool migration_happened(lmdb::Transaction& txn, const char* name) {
    std::unique_ptr<lmdb::Table> migration_table{txn.open(db::table::kMigrations)};
    return migration_table->get(byte_view_of_c_str(name)).has_value();
}

int main(int argc, char* argv[]) {
    CLI::App app{"Execute Ethereum blocks and write the result into the DB"};

    std::string db_path{db::default_path()};
    app.add_option("-d,--datadir", db_path, "Path to a database populated by Turbo-Geth");

    uint64_t to_block{std::numeric_limits<uint64_t>::max()};
    app.add_option("--to", to_block, "Block execute up to");

    size_t batch_mib{512};
    app.add_option("--batch_mib", batch_mib, "Batch size in mebibytes of DB changes to accumulate before committing");

    CLI11_PARSE(app, argc, argv);

    BOOST_LOG_TRIVIAL(info) << "Starting block execution. DB: " << db_path;

    lmdb::options opts{};
    opts.read_only = false;
    std::shared_ptr<lmdb::Environment> env{lmdb::get_env(db_path.c_str(), opts)};
    std::unique_ptr<lmdb::Transaction> txn{env->begin_rw_transaction()};

    bool write_receipts{db::read_storage_mode_receipts(*txn)};
    if (write_receipts && (!migration_happened(*txn, "receipts_cbor_encode") ||
                           !migration_happened(*txn, "receipts_store_logs_separately"))) {
        BOOST_LOG_TRIVIAL(error) << "Legacy stored receipts are not supported";
        return -1;
    }

    auto buffer{std::make_unique<db::Buffer>(txn.get())};

    uint64_t previous_progress{already_executed_block(*txn)};
    uint64_t current_progress{0};

    for (uint64_t block_number{previous_progress + 1}; block_number <= to_block; ++block_number) {
        std::optional<BlockWithHash> bh{db::read_block(*txn, block_number, /*read_senders=*/true)};
        if (!bh) {
            break;
        }

        std::vector<Receipt> receipts{execute_block(bh->block, *buffer)};

        if (write_receipts) {
            buffer->insert_receipts(block_number, receipts);
        }

        current_progress = block_number;
        if (current_progress % 1000 == 0) {
            BOOST_LOG_TRIVIAL(info) << "Blocks <= " << current_progress << " executed";
        }

        if (buffer->current_batch_size() >= batch_mib * kMiB) {
            buffer->write_to_db();
            save_progress(*txn, current_progress);
            lmdb::err_handler(txn->commit());

            BOOST_LOG_TRIVIAL(info) << "Blocks <= " << current_progress << " committed";

            txn = env->begin_rw_transaction();
            buffer = std::make_unique<db::Buffer>(txn.get());
        }
    }

    if (current_progress) {
        buffer->write_to_db();
        save_progress(*txn, current_progress);
        lmdb::err_handler(txn->commit());
        BOOST_LOG_TRIVIAL(info) << "All blocks <= " << current_progress << " executed and committed";
    } else {
        BOOST_LOG_TRIVIAL(warning) << "Nothing to execute";
    }

    return 0;
}
