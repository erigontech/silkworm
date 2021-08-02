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

#include <silkworm/common/data_dir.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/etl/collector.hpp>

using namespace silkworm;
namespace fs = std::filesystem;

enum Operation {
    HashAccount,
    HashStorage,
    Code,
};

std::pair<db::MapConfig, db::MapConfig> get_tables_for_checking(Operation operation) {
    switch (operation) {
        case HashAccount:
            return {db::table::kPlainState, db::table::kHashedAccounts};
        case HashStorage:
            return {db::table::kPlainState, db::table::kHashedStorage};
        default:
            return {db::table::kPlainContractCode, db::table::kContractCode};
    }
}

void check(mdbx::txn& txn, Operation operation) {
    auto [source_config, target_config] = get_tables_for_checking(operation);
    auto source_table{db::open_cursor(txn, source_config)};
    auto target_table{db::open_cursor(txn, target_config)};
    auto data{source_table.to_first(/*throw_notfound*/ false)};

    while (data) { /* Loop as long as we have no errors*/
        Bytes mdb_key_as_bytes{db::from_slice(data.key)};

        if (operation == HashAccount) {
            // Account
            if (data.key.length() != kAddressLength) {
                data = source_table.to_next(false);
                continue;
            }
            auto hash{keccak256(mdb_key_as_bytes)};
            auto key{full_view(hash.bytes)};

            auto actual_value{target_table.find(db::to_slice(key))};
            if (!actual_value) {
                SILKWORM_LOG(LogLevel::Error) << "key: " << to_hex(key) << ", does not exist." << std::endl;
                return;
            }
            if (actual_value.value != data.value) {
                SILKWORM_LOG(LogLevel::Error) << "Expected: " << to_hex(db::from_slice(data.value)) << ", Actual: << "
                                              << to_hex(db::from_slice(actual_value.value)) << std::endl;
                return;
            }
            data = source_table.to_next(false);

        } else if (operation == HashStorage) {
            // Storage
            if (data.key.length() != kAddressLength) {
                data = source_table.to_next(false);
                continue;
            }

            Bytes key(kHashLength * 2 + db::kIncarnationLength, '\0');
            std::memcpy(&key[0], keccak256(mdb_key_as_bytes.substr(0, kAddressLength)).bytes, kHashLength);
            std::memcpy(&key[kHashLength], &mdb_key_as_bytes[kAddressLength], db::kIncarnationLength);
            std::memcpy(&key[kHashLength + db::kIncarnationLength],
                        keccak256(mdb_key_as_bytes.substr(kAddressLength + db::kIncarnationLength)).bytes, kHashLength);

            auto target_data{target_table.find_multivalue(db::to_slice(key), data.value, /*throw_notfound*/ false)};
            if (!target_data) {
                SILKWORM_LOG(LogLevel::Error) << "Key: " << to_hex(key) << ", does not exist." << std::endl;
                return;
            }
            data = source_table.to_next(false);

        } else {
            // Code
            if (data.key.length() != kAddressLength + db::kIncarnationLength) {
                data = source_table.to_next(false);
                continue;
            }
            Bytes key(kHashLength + db::kIncarnationLength, '\0');
            std::memcpy(&key[0], keccak256(mdb_key_as_bytes.substr(0, kAddressLength)).bytes, kHashLength);
            std::memcpy(&key[kHashLength], &mdb_key_as_bytes[kAddressLength], db::kIncarnationLength);
            auto actual_value{target_table.find(db::to_slice(key), /*throw_notfound*/ false)};
            if (!actual_value) {
                SILKWORM_LOG(LogLevel::Error) << "Key: " << to_hex(key) << ", does not exist." << std::endl;
                data = source_table.to_next(false);
                continue;
            }
            if (actual_value.value != data.value) {
                SILKWORM_LOG(LogLevel::Error) << "Expected: " << to_hex(db::from_slice(data.value)) << ", Actual: << "
                                              << to_hex(db::from_slice(actual_value.value)) << std::endl;
                return;
            }
            data = source_table.to_next(false);
        }
    }
}

int main(int argc, char* argv[]) {
    CLI::App app{"Check Hashed state"};

    std::string chaindata{DataDirectory{}.get_chaindata_path().string()};
    app.add_option("--chaindata", chaindata, "Path to a database populated by Erigon", true)
        ->check(CLI::ExistingDirectory);
    CLI11_PARSE(app, argc, argv);
    SILKWORM_LOG(LogLevel::Info) << "Checking HashState" << std::endl;

    try {
        auto data_dir{DataDirectory::from_chaindata(chaindata)};
        data_dir.create_tree();
        db::EnvConfig db_config{data_dir.get_chaindata_path().string()};
        auto env{db::open_env(db_config)};
        auto txn{env.start_write()};

        SILKWORM_LOG(LogLevel::Info) << "Checking Accounts" << std::endl;
        check(txn, HashAccount);
        SILKWORM_LOG(LogLevel::Info) << "Checking Storage" << std::endl;
        check(txn, HashStorage);
        SILKWORM_LOG(LogLevel::Info) << "Checking Code Keys" << std::endl;
        check(txn, Code);
        SILKWORM_LOG(LogLevel::Info) << "All Done!" << std::endl;
    } catch (const std::exception& ex) {
        SILKWORM_LOG(LogLevel::Error) << ex.what() << std::endl;
        return -5;
    }
}
