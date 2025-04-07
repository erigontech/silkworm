// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <iostream>

#include <CLI/CLI.hpp>

#include <silkworm/db/tables.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/common/log.hpp>

using namespace silkworm;
using namespace silkworm::db;
using namespace silkworm::datastore::kvdb;

enum Operation {
    kHashAccount,
    kHashStorage,
    kCode,
};

std::pair<MapConfig, MapConfig> get_tables_for_checking(Operation operation) {
    switch (operation) {
        case kHashAccount:
            return {table::kPlainState, table::kHashedAccounts};
        case kHashStorage:
            return {table::kPlainState, table::kHashedStorage};
        default:
            return {table::kPlainCodeHash, table::kHashedCodeHash};
    }
}

void check(mdbx::txn& txn, Operation operation) {
    auto [source_config, target_config] = get_tables_for_checking(operation);
    auto source_table{open_cursor(txn, source_config)};
    auto target_table{open_cursor(txn, target_config)};
    auto data{source_table.to_first(/*throw_notfound*/ false)};

    while (data) { /* Loop as long as we have no errors*/
        Bytes mdb_key_as_bytes{from_slice(data.key)};

        if (operation == kHashAccount) {
            // Account
            if (data.key.length() != kAddressLength) {
                data = source_table.to_next(false);
                continue;
            }
            auto hash{keccak256(mdb_key_as_bytes)};
            ByteView key{hash.bytes};

            auto actual_value{target_table.find(to_slice(key))};
            if (!actual_value) {
                SILK_ERROR << "key: " << to_hex(key) << ", does not exist.";
                return;
            }
            if (actual_value.value != data.value) {
                SILK_ERROR << "Expected: " << to_hex(from_slice(data.value)) << ", Actual: << "
                           << to_hex(from_slice(actual_value.value));
                return;
            }
            data = source_table.to_next(false);

        } else if (operation == kHashStorage) {
            // Storage
            if (data.key.length() != kAddressLength) {
                data = source_table.to_next(false);
                continue;
            }

            Bytes key(kHashLength * 2 + kIncarnationLength, '\0');
            std::memcpy(&key[0], keccak256(mdb_key_as_bytes.substr(0, kAddressLength)).bytes, kHashLength);
            std::memcpy(&key[kHashLength], &mdb_key_as_bytes[kAddressLength], kIncarnationLength);
            std::memcpy(&key[kHashLength + kIncarnationLength],
                        keccak256(mdb_key_as_bytes.substr(kAddressLength + kIncarnationLength)).bytes, kHashLength);

            auto target_data{target_table.find_multivalue(to_slice(key), data.value, /*throw_notfound*/ false)};
            if (!target_data) {
                SILK_ERROR << "Key: " << to_hex(key) << ", does not exist.";
                return;
            }
            data = source_table.to_next(false);

        } else {
            // Code
            if (data.key.length() != kAddressLength + kIncarnationLength) {
                data = source_table.to_next(false);
                continue;
            }
            Bytes key(kHashLength + kIncarnationLength, '\0');
            std::memcpy(&key[0], keccak256(mdb_key_as_bytes.substr(0, kAddressLength)).bytes, kHashLength);
            std::memcpy(&key[kHashLength], &mdb_key_as_bytes[kAddressLength], kIncarnationLength);
            auto actual_value{target_table.find(to_slice(key), /*throw_notfound*/ false)};
            if (!actual_value) {
                SILK_ERROR << "Key: " << to_hex(key) << ", does not exist.";
                data = source_table.to_next(false);
                continue;
            }
            if (actual_value.value != data.value) {
                SILK_ERROR << "Expected: " << to_hex(from_slice(data.value)) << ", Actual: << "
                           << to_hex(from_slice(actual_value.value));
                return;
            }
            data = source_table.to_next(false);
        }
    }
}

int main(int argc, char* argv[]) {
    CLI::App app{"Check Hashed state"};

    std::string chaindata{DataDirectory{}.chaindata().path().string()};
    app.add_option("--chaindata", chaindata, "Path to a database populated by Erigon")
        ->capture_default_str()
        ->check(CLI::ExistingDirectory);
    CLI11_PARSE(app, argc, argv);
    SILK_INFO << "Checking HashState";

    try {
        auto data_dir{DataDirectory::from_chaindata(chaindata)};
        data_dir.deploy();
        EnvConfig db_config{data_dir.chaindata().path().string()};
        auto env{open_env(db_config)};
        auto txn{env.start_write()};

        SILK_INFO << "Checking Accounts";
        check(txn, kHashAccount);
        SILK_INFO << "Checking Storage";
        check(txn, kHashStorage);
        SILK_INFO << "Checking Code Keys";
        check(txn, kCode);
        SILK_INFO << "All Done!";
    } catch (const std::exception& ex) {
        SILK_ERROR << ex.what();
        return -5;
    }
}
