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

#include <CLI/CLI.hpp>
#include <boost/endian/conversion.hpp>
#include <boost/filesystem.hpp>
#include <iostream>
#include <silkworm/common/log.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/etl/collector.hpp>

using namespace silkworm;

int main(int argc, char* argv[]) {
    namespace fs = boost::filesystem;

    CLI::App app{"Generates Blockhashes => BlockNumber mapping in database"};

    std::string db_path{db::default_path()};
    app.add_option("-d,--datadir", db_path, "Path to a database populated by Turbo-Geth", true)
        ->check(CLI::ExistingDirectory);
    CLI11_PARSE(app, argc, argv);

    Logger::default_logger().set_local_timezone(true);  // for compatibility with TG logging

    // Check data.mdb exists in provided directory
    boost::filesystem::path db_file{boost::filesystem::path(db_path) / boost::filesystem::path("data.mdb")};
    if (!boost::filesystem::exists(db_file)) {
        SILKWORM_LOG(LogError) << "Can't find a valid TG data file in " << db_path << std::endl;
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
    auto header_table{txn->open(db::table::kBlockHeaders)};
    auto blockhashes_table{txn->open(db::table::kHeaderNumbers)};

    try {

        auto last_processed_block_number{db::stages::get_stage_progress(*txn, db::stages::kBlockHashesKey)};
        auto expected_block_number{last_processed_block_number + 1};
        uint32_t block_number{0};
        uint32_t blocks_processed_count{0};

        // Extract
        Bytes start(8, '\0');
        boost::endian::store_big_u64(&start[0], expected_block_number);
        MDB_val mdb_key{db::to_mdb_val(start)};
        MDB_val mdb_data;
        SILKWORM_LOG(LogInfo) << "Started BlockHashes Extraction" << std::endl;
        int rc{header_table->seek(&mdb_key, &mdb_data)};  // Sets cursor to nearest key greater equal than this
        while (!rc) { /* Loop as long as we have no errors*/

            if (mdb_key.mv_size != 40) {
                // Not the key we need
                rc = header_table->get_next(&mdb_key, &mdb_data);
                continue;
            }

            // Ensure the reached block number is in proper sequence
            Bytes mdb_key_as_bytes{static_cast<uint8_t*>(mdb_key.mv_data), mdb_key.mv_size};
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
            etl::Entry etl_entry{mdb_key_as_bytes.substr(8, 40), mdb_key_as_bytes.substr(0, 8)};
            collector.collect(etl_entry);

            // Save last processed block_number and expect next in sequence
            ++blocks_processed_count;
            block_number = expected_block_number++;
            rc = header_table->get_next(&mdb_key, &mdb_data);
        }

        if (rc && rc != MDB_NOTFOUND) { /* MDB_NOTFOUND is not actually an error rather eof */
            lmdb::err_handler(rc);
        }


        SILKWORM_LOG(LogInfo) << "Entries Collected << " << blocks_processed_count << std::endl;

        // Proceed only if we've done something
        if (blocks_processed_count) {
            SILKWORM_LOG(LogInfo) << "Started BlockHashes Loading" << std::endl;

            // Ensure we haven't got dirty data in target table
            auto target_table{txn->open(db::table::kHeaderNumbers, MDB_CREATE)};

            if (last_processed_block_number <= 1) {
                lmdb::err_handler(target_table->clear());
            } else {
                boost::endian::store_big_u64(&start[0], last_processed_block_number + 1);
                mdb_key = db::to_mdb_val(start);
                rc = target_table->seek_exact(&mdb_key, &mdb_data);
                while (!rc) {
                    lmdb::err_handler(target_table->del_current());
                    rc = target_table->get_next(&mdb_key, &mdb_data);
                }
                if (rc != MDB_NOTFOUND) {
                    lmdb::err_handler(rc);
                }
            }

            // << -- Up to here
            // Eventually bulk load collected items with no transform (may throw)
            collector.load(target_table.get(), nullptr, MDB_APPEND, /* log_progress = */ true);

            // Update progress height with last processed block
            db::stages::set_stage_progress(*txn, db::stages::kBlockHashesKey, block_number);
            lmdb::err_handler(txn->commit());

        } else {
            SILKWORM_LOG(LogInfo) << "Nothing to process" << std::endl;
        }

        SILKWORM_LOG(LogInfo) << "All Done" << std::endl;
    } catch (const std::exception& ex) {
        SILKWORM_LOG(LogError) << ex.what() << std::endl;
        return -5;
    }
    return 0;
}
