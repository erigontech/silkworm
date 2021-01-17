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
#include <silkworm/db/tables.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/db/stages.hpp>
#include <boost/endian/conversion.hpp>
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
    // We take data from header table and transform it and put it in blockhashes table
    auto header_table{txn->open(db::table::kBlockHeaders)};
    auto blockhashes_table{txn->open(db::table::kHeaderNumbers)};
    
    try {
        auto current_block_number{db::stages::get_stage_progress(*txn, db::stages::kBlockHashesKey)};
        auto initial_block_number = current_block_number;
        // Extract
        Bytes start(8, '\0');
        boost::endian::store_big_u64(&start[0], current_block_number);
        MDB_val key_mdb{db::to_mdb_val(start)};
        MDB_val data_mdb;
        SILKWORM_LOG(LogInfo) << "Started BlockHashes Extraction" << std::endl;

        for (int rc{header_table->seek(&key_mdb, &data_mdb)}; rc != MDB_NOTFOUND; rc = header_table->get_next(&key_mdb, &data_mdb)) {
            // Check if it's an header entry
            if (key_mdb.mv_size != 40) continue;
            Bytes key(static_cast<unsigned char*>(key_mdb.mv_data), key_mdb.mv_size);
            // We set the key to the hash of the header and the value to the block number
            etl::Entry entry{key.substr(8,40), key.substr(0,8)};
            collector.collect(entry);
            current_block_number++;
        }
        SILKWORM_LOG(LogInfo) << "Entries Inserted << " << current_block_number - initial_block_number << std::endl;
        SILKWORM_LOG(LogInfo) << "Started BlockHashes Loading" << std::endl;
        // If it was not empty before appending cannot happen
        if (initial_block_number == 0) {
            // It First clear from temporary data generated in Stage 1
            txn->open(db::table::kHeaderNumbers)->clear();
            collector.load(blockhashes_table.get(), nullptr, MDB_APPEND);
        } else {
            collector.load(blockhashes_table.get(), nullptr, 0);
        }
        // Update progress
        db::stages::set_stage_progress(*txn, db::stages::kBlockHashesKey, current_block_number-1);
        lmdb::err_handler(txn->commit());
        SILKWORM_LOG(LogInfo) << "All Done" << std::endl;
    } catch (const std::exception& ex) {
        SILKWORM_LOG(LogError) << ex.what() << std::endl;
        return -5;
    }
    return 0;
}
