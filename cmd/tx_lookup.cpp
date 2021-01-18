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

    CLI::App app{"Generates Tc Hashes => BlockNumber mapping in database"};

    std::string db_path{db::default_path()};
    bool full;
    app.add_option("-d,--datadir", db_path, "Path to a database populated by Turbo-Geth", true)
        ->check(CLI::ExistingDirectory);

    app.add_flag("--full", full, "Start making lookups from block 0");
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
    auto bodies_table{txn->open(db::table::kBlockBodies)};
    auto transactions_table{txn->open(db::table::kEthTx)};

    try {
        auto last_processed_block_number{db::stages::get_stage_progress(*txn, db::stages::kTxLookupKey)};
        if (full) {
            last_processed_block_number = 0;
        }
        auto expected_block_number{last_processed_block_number + 1};
        uint32_t block_number{0};
        uint32_t entries_processed_count{0};

        // Extract
        Bytes start(8, '\0');
        boost::endian::store_big_u64(&start[0], expected_block_number);
        MDB_val mdb_key{db::to_mdb_val(start)};
        MDB_val mdb_data;
        SILKWORM_LOG(LogInfo) << "Started Tx Lookup Extraction" << std::endl;
        int rc{bodies_table->seek(&mdb_key, &mdb_data)};  // Sets cursor to nearest key greater equal than this
        while (!rc) { /* Loop as long as we have no errors*/
            auto body_rlp{db::from_mdb_val(mdb_data)};
            auto body{db::detail::decode_stored_block_body(body_rlp)};
            Bytes block_number(static_cast<unsigned char*>(mdb_key.mv_data), 8);

            if (body.txn_count > 0) {
                Bytes transaction_key(8, '\0');
                boost::endian::store_big_u64(transaction_key.data(), body.base_txn_id);
                MDB_val tx_key_mdb{db::to_mdb_val(transaction_key)};
                MDB_val tx_data_mdb{};

                uint64_t i{0};
                for (int rc{transactions_table->seek_exact(&tx_key_mdb, &tx_data_mdb)}; rc != MDB_NOTFOUND && i < body.txn_count; rc = transactions_table->get_next(&tx_key_mdb, &tx_data_mdb), ++i) {
                    lmdb::err_handler(rc);
                    // Take transaction rlp, then hash it in order to get the transaction hash
                    ByteView tx_rlp{db::from_mdb_val(tx_data_mdb)};
                    auto hash{keccak256(tx_rlp)};
                    etl::Entry entry{Bytes(hash.bytes, 32), block_number};
                    collector.collect(entry);
                    ++entries_processed_count;
                }
            }
            // Save last processed block_number and expect next in sequence
            block_number = expected_block_number++;
            rc = bodies_table->get_next(&mdb_key, &mdb_data);
        }

        if (rc && rc != MDB_NOTFOUND) { /* MDB_NOTFOUND is not actually an error rather eof */
            lmdb::err_handler(rc);
        }


        SILKWORM_LOG(LogInfo) << "Entries Collected << " << entries_processed_count << std::endl;

        // Proceed only if we've done something
        if (entries_processed_count) {
            SILKWORM_LOG(LogInfo) << "Started tx Hashes Loading" << std::endl;

            // Ensure we haven't got dirty data in target table
            auto target_table{txn->open(db::table::kTxLookup, MDB_CREATE)};

            if (last_processed_block_number <= 1) {
                lmdb::err_handler(txn->open(db::table::kTxLookup)->clear());
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

            // Eventually bulk load collected items with no transform (may throw)
            collector.load(target_table.get(), nullptr, MDB_APPEND);

            // Update progress height with last processed block
            db::stages::set_stage_progress(*txn, db::stages::kTxLookupKey, block_number);
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
