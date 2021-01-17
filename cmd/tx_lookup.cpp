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

#include <boost/filesystem.hpp>
#include <silkworm/etl/collector.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/crypto/ecdsa.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/types/transaction.hpp>
#include <boost/endian/conversion.hpp>
#include <silkworm/chain/config.hpp>
#include <iostream>

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

    auto bodies_table{txn->open(db::table::kBlockBodies)};
    auto tx_lookup_table{txn->open(db::table::kTxLookup)};
    auto transactions_table{txn->open(db::table::kEthTx)};

    try {
        auto initial_block_number{db::stages::get_stage_progress(*txn, db::stages::kTxLookupKey)};
        // Extract
        Bytes start(8, '\0');
        boost::endian::store_big_u64(&start[0], initial_block_number);
        uint64_t current_block_number{initial_block_number};
        MDB_val key_mdb{db::to_mdb_val(start)};
        MDB_val data_mdb;
        SILKWORM_LOG(LogInfo) << "Started Transaction Lookup Extraction" << std::endl;
        uint64_t total_entries = 0;
        for (int rc{bodies_table->seek(&key_mdb, &data_mdb)}; rc != MDB_NOTFOUND; rc = bodies_table->get_next(&key_mdb, &data_mdb)) {
            auto body_rlp{db::from_mdb_val(data_mdb)};
            auto body{db::detail::decode_stored_block_body(body_rlp)};
            Bytes block_number(static_cast<unsigned char*>(key_mdb.mv_data), 8);

            if (body.txn_count == 0) {
                current_block_number++;
                continue;
            }
            Bytes transaction_key(8, '\0');
            boost::endian::store_big_u64(transaction_key.data(), body.base_txn_id);
            MDB_val tx_key_mdb{db::to_mdb_val(transaction_key)};
            MDB_val tx_data_mdb{};

            uint64_t i{0};
            for (int rc{transactions_table->seek_exact(&tx_key_mdb, &tx_data_mdb)}; rc != MDB_NOTFOUND && i < body.txn_count; rc = transactions_table->get_next(&tx_key_mdb, &tx_data_mdb), ++i) {
                // Take transaction rlp, then hash it in order to get the transaction hash
                ByteView tx_rlp{db::from_mdb_val(tx_data_mdb)};
                auto hash{keccak256(tx_rlp)};
                total_entries++;
                etl::Entry entry{Bytes(hash.bytes, 32), block_number};
                collector.collect(entry);
            }
            current_block_number++;
        }
        SILKWORM_LOG(LogInfo) << "Entries to be inserted << " << total_entries << std::endl;
        SILKWORM_LOG(LogInfo) << "Started Transaction Lookup Loading" << std::endl;
        // If it was not empty before appending cannot happen
        if (initial_block_number == 0) {
            // Clear lookups just to be sure there is no garbage when append is enabled
            txn->open(db::table::kTxLookup)->clear();
            collector.load(tx_lookup_table.get(), nullptr, MDB_APPEND);
        } else {
            collector.load(tx_lookup_table.get(), nullptr, 0);
        }
        // Update progress
        db::stages::set_stage_progress(*txn, db::stages::kTxLookupKey, current_block_number);
        lmdb::err_handler(txn->commit());
        SILKWORM_LOG(LogInfo) << "All Done" << std::endl;
    } catch (const std::exception& ex) {
        SILKWORM_LOG(LogError) << ex.what() << std::endl;
        return -5;
    }
    return 0;
}
