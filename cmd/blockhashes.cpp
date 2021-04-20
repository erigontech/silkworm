/*
   Copyright 2021 The Silkworm Authors

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

#include <filesystem>
#include <iostream>

#include <CLI/CLI.hpp>
#include <boost/endian/conversion.hpp>

#include <silkworm/common/log.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/etl/collector.hpp>

using namespace silkworm;

int main(int argc, char* argv[]) {
    namespace fs = std::filesystem;

    CLI::App app{"Generates Blockhashes => BlockNumber mapping in database"};

    std::string db_path{db::default_path()};
    app.add_option("--chaindata", db_path, "Path to a database populated by Turbo-Geth", true)
        ->check(CLI::ExistingDirectory);
    CLI11_PARSE(app, argc, argv);

    // Check data.mdb exists in provided directory
    fs::path db_file{fs::path(db_path) / fs::path("data.mdb")};
    if (!fs::exists(db_file)) {
        SILKWORM_LOG(LogLevel::Error) << "Can't find a valid TG data file in " << db_path << std::endl;
        return -1;
    }
    fs::path datadir(db_path);
    fs::path etl_path(datadir.parent_path() / fs::path("etl-temp"));
    fs::create_directories(etl_path);
    etl::Collector collector(etl_path.string().c_str(), /* flush size */ 512 * kMebi);

    lmdb::DatabaseConfig db_config{db_path};
    db_config.set_readonly(false);
    std::shared_ptr<lmdb::Environment> env{lmdb::get_env(db_config)};
    std::unique_ptr<lmdb::Transaction> txn{env->begin_rw_transaction()};
    // We take data from header table and transform it and put it in blockhashes table
    auto canonical_hashes_table{txn->open(db::table::kCanonicalHashes)};
    auto blockhashes_table{txn->open(db::table::kHeaderNumbers)};

    try {
        auto last_processed_block_number{db::stages::get_stage_progress(*txn, db::stages::kBlockHashesKey)};
        auto expected_block_number{last_processed_block_number + 1};
        uint32_t block_number{0};
        uint32_t blocks_processed_count{0};

        // Extract
        auto header_key{db::block_key(expected_block_number)};
        MDB_val mdb_key{db::to_mdb_val(header_key)}, mdb_data{};

        SILKWORM_LOG(LogLevel::Info) << "Started BlockHashes Extraction" << std::endl;
        int rc{canonical_hashes_table->seek_exact(&mdb_key, &mdb_data)};  // Sets cursor to matching header
        while (!rc) {                                                     /* Loop as long as we have no errors*/

            if (mdb_data.mv_size != kHashLength) {
                throw std::runtime_error("Invalid header hash for block " + std::to_string(expected_block_number));
            }

            // Ensure the reached block number is in proper sequence
            Bytes mdb_key_as_bytes{db::from_mdb_val(mdb_key)};
            auto reached_block_number{boost::endian::load_big_u64(&mdb_key_as_bytes[0])};
            if (reached_block_number != expected_block_number) {
                // Something wrong with db
                // Blocks are out of sequence for any reason
                // Should not happen but you never know
                throw std::runtime_error("Bad headers sequence. Expected " + std::to_string(expected_block_number) +
                                         " got " + std::to_string(reached_block_number));
            }

            // We reached a valid block height in proper sequence
            // Load data into collector
            Bytes mdb_data_as_bytes{db::from_mdb_val(mdb_data)};
            etl::Entry etl_entry{/* hash */ mdb_data_as_bytes, /* block number */ mdb_key_as_bytes};
            collector.collect(etl_entry);

            // Save last processed block_number and expect next in sequence
            ++blocks_processed_count;
            block_number = expected_block_number++;
            rc = canonical_hashes_table->get_next(&mdb_key, &mdb_data);
        }

        if (rc && rc != MDB_NOTFOUND) { /* MDB_NOTFOUND is not actually an error rather eof */
            lmdb::err_handler(rc);
        }

        SILKWORM_LOG(LogLevel::Info) << "Entries Collected << " << blocks_processed_count << std::endl;

        // Proceed only if we've done something
        if (blocks_processed_count) {
            SILKWORM_LOG(LogLevel::Info) << "Started BlockHashes Loading" << std::endl;

            /*
             * If we're on first sync then we shouldn't have any records in target
             * table. For this reason we can apply MDB_APPEND to load as
             * collector (with no transform) ensures collected entries
             * are already sorted. If instead target table contains already
             * some data the only option is to load in upsert mode as we
             * cannot guarantee keys are sorted amongst different calls
             * of this stage
             */
            auto target_table{txn->open(db::table::kHeaderNumbers, MDB_CREATE)};
            size_t target_table_rcount{0};
            lmdb::err_handler(target_table->get_rcount(&target_table_rcount));
            unsigned int db_flags{target_table_rcount ? 0u : MDB_APPEND};

            // Eventually load collected items with no transform (may throw)
            collector.load(target_table.get(), nullptr, db_flags, /* log_every_percent = */ 10);

            // Update progress height with last processed block
            db::stages::set_stage_progress(*txn, db::stages::kBlockHashesKey, block_number);
            lmdb::err_handler(txn->commit());

        } else {
            SILKWORM_LOG(LogLevel::Info) << "Nothing to process" << std::endl;
        }

        SILKWORM_LOG(LogLevel::Info) << "All Done" << std::endl;
    } catch (const std::exception& ex) {
        SILKWORM_LOG(LogLevel::Error) << ex.what() << std::endl;
        return -5;
    }
    return 0;
}
