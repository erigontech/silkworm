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
namespace fs = boost::filesystem;

enum Operation {
    HashAccount,
    HashStorage,
    Code
};

std::pair<lmdb::TableConfig, lmdb::TableConfig> get_tables_for_checking(Operation operation) {
    switch (operation) {
        case HashAccount:
            return {db::table::kPlainState, db::table::kHashedAccounts};
        case HashStorage:
            return {db::table::kPlainState, db::table::kHashedStorage};
        default:
            return {db::table::kPlainContractCode, db::table::kContractCode};
    }

}
void check(lmdb::Transaction * txn, Operation operation) {
    auto [source_config, target_config] = get_tables_for_checking(operation);
    auto source_table{txn->open(source_config)};
    auto target_table{txn->open(target_config)};
    MDB_val mdb_key{db::to_mdb_val(Bytes(8, '\0'))};
    MDB_val mdb_data;
    int rc{source_table->seek(&mdb_key, &mdb_data)};
    while (!rc) { /* Loop as long as we have no errors*/
        Bytes mdb_key_as_bytes{static_cast<uint8_t*>(mdb_key.mv_data), mdb_key.mv_size};
        Bytes expected_value{static_cast<uint8_t*>(mdb_data.mv_data), mdb_data.mv_size};

        if (operation == HashAccount) {
            // Account
            if (mdb_key.mv_size != kAddressLength) {
                rc = source_table->get_next(&mdb_key, &mdb_data);
                continue; 
            }
            auto hash{keccak256(mdb_key_as_bytes)};
            auto key{full_view(hash.bytes)};
            auto actual_value{target_table->get(key)};
            if (actual_value == std::nullopt) {
                SILKWORM_LOG(LogError) << "key: " << to_hex(key) << ", does not exist." << std::endl;
                return;
            }
            if (actual_value->compare(expected_value) != 0) {
                SILKWORM_LOG(LogError) << "Expected: " << to_hex(expected_value) << ", Actual: << " << to_hex(*actual_value) << std::endl;
                return;
            }
            rc = source_table->get_next(&mdb_key, &mdb_data);
        } else if (operation == HashStorage) {
            // Storage
            if (mdb_key.mv_size == kAddressLength) {
                rc = source_table->get_next(&mdb_key, &mdb_data);
                continue;
            }
            Bytes key(kHashLength*2+db::kIncarnationLength, '\0');
            std::memcpy(&key[0], keccak256(mdb_key_as_bytes.substr(0, kAddressLength)).bytes, kHashLength);
            std::memcpy(&key[kHashLength], &mdb_key_as_bytes[kAddressLength], db::kIncarnationLength);
            std::memcpy(&key[kHashLength + db::kIncarnationLength], keccak256(mdb_key_as_bytes.substr(kAddressLength + db::kIncarnationLength)).bytes, kHashLength);
            MDB_val mdb_key_hashed{db::to_mdb_val(key)};
            MDB_val mdb_data_hashed{db::to_mdb_val(expected_value)};
            rc = target_table->seek_exact(&mdb_key_hashed, &mdb_data_hashed);
            if (rc != 0) {
                SILKWORM_LOG(LogError) << "Key: " << to_hex(key) << ", does not exist." << std::endl;
                return;
            }
            rc = source_table->get_next(&mdb_key, &mdb_data);
        } else {
            // Code
            if (mdb_key.mv_size != kAddressLength+db::kIncarnationLength) {
                rc = source_table->get_next(&mdb_key, &mdb_data);
                continue;
            }
            Bytes key(kHashLength+db::kIncarnationLength, '\0');            
            std::memcpy(&key[0], keccak256(mdb_key_as_bytes.substr(0, kAddressLength)).bytes, kHashLength);
            std::memcpy(&key[kHashLength], &mdb_key_as_bytes[kAddressLength], db::kIncarnationLength);
            auto actual_value{target_table->get(key)};
            if (actual_value == std::nullopt) {
                SILKWORM_LOG(LogError) << "Key: " << to_hex(key) << ", does not exist." << std::endl;
                rc = source_table->get_next(&mdb_key, &mdb_data);
                continue;
            }

            if (actual_value->compare(expected_value) != 0) {
                SILKWORM_LOG(LogError) << "Expected: " << to_hex(expected_value) << ", Actual: << " << to_hex(*actual_value) << std::endl;
                return;
            }
            rc = source_table->get_next(&mdb_key, &mdb_data);
        }
    }

    if (rc && rc != MDB_NOTFOUND) { /* MDB_NOTFOUND is not actually an error rather eof */
        lmdb::err_handler(rc);
    }
}

int main(int argc, char* argv[]) {
    CLI::App app{"Check Hashed state"};

    std::string db_path{db::default_path()};
    app.add_option("-d,--datadir", db_path, "Path to a database populated by Turbo-Geth", true)
        ->check(CLI::ExistingDirectory);
    CLI11_PARSE(app, argc, argv);
    SILKWORM_LOG(LogInfo) << "Checking HashState" << std::endl;


    // Check data.mdb exists in provided directory
    boost::filesystem::path db_file{boost::filesystem::path(db_path) / boost::filesystem::path("data.mdb")};
    if (!boost::filesystem::exists(db_file)) {
        SILKWORM_LOG(LogError) << "Can't find a valid TG data file in " << db_path << std::endl;
        return -1;
    }
    fs::path datadir(db_path);
    fs::path etl_path(datadir.parent_path() / fs::path("etl-temp"));

    lmdb::DatabaseConfig db_config{db_path};
    db_config.set_readonly(false);
    std::shared_ptr<lmdb::Environment> env{lmdb::get_env(db_config)};
    std::unique_ptr<lmdb::Transaction> txn{env->begin_rw_transaction()};

    try {
        SILKWORM_LOG(LogInfo) << "Checking Accounts" << std::endl;
        check(txn.get(), HashAccount);
        SILKWORM_LOG(LogInfo) << "Checking Storage" << std::endl;
        check(txn.get(), HashStorage);
        SILKWORM_LOG(LogInfo) << "Checking Code Keys" << std::endl;
        check(txn.get(), Code);
        SILKWORM_LOG(LogInfo) << "All Done!" << std::endl;
    } catch (const std::exception& ex) {
        SILKWORM_LOG(LogError) << ex.what() << std::endl;
        return -5;
    }
}
