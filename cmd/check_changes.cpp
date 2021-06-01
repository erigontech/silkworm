/*
   Copyright 2020-2021 The Silkworm Authors

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
#include <absl/container/flat_hash_set.h>
#include <absl/time/time.h>

#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/buffer.hpp>
#include <silkworm/execution/execution.hpp>

using namespace evmc::literals;
using namespace silkworm;

// Non-existing accounts only touched by zero-value internal transactions:
// e.g. https://etherscan.io/address/0x000000000000000000636f6e736f6c652e6c6f67
static const absl::flat_hash_set<evmc::address> kPhantomAccounts{
    0x000000000000000000636f6e736f6c652e6c6f67_address,
    0x2386f26fc10000b4e16d0168e52d35cacd2c6185_address,
    0x5a719cf3e02c17c876f6d294adb5cb7c6eb47e2f_address,
};

static void print_storage_changes(const db::StorageChanges& s) {
    for (const auto& [address, x] : s) {
        std::cout << to_hex(address) << "\n";
        for (const auto& [incarnation, changes] : x) {
            std::cout << "  " << incarnation << "\n";
            for (const auto& [location, value] : changes) {
                std::cout << "    " << to_hex(location) << " = " << to_hex(value) << "\n";
            }
        }
    }
}

int main(int argc, char* argv[]) {
    CLI::App app{"Executes Ethereum blocks and compares resulting change sets against DB"};

    std::string db_path{db::default_path()};
    app.add_option("--chaindata", db_path, "Path to a database populated by Erigon", true)
        ->check(CLI::ExistingDirectory);

    uint64_t from{1};
    app.add_option("--from", from, "start from block number (inclusive)");

    uint64_t to{UINT64_MAX};
    app.add_option("--to", to, "check up to block number (exclusive)");

    CLI11_PARSE(app, argc, argv);

    absl::Time t1{absl::Now()};
    std::cout << t1 << " Checking change sets in " << db_path << "\n";

    lmdb::DatabaseConfig db_config{db_path};
    std::shared_ptr<lmdb::Environment> env{lmdb::get_env(db_config)};

    std::unique_ptr<lmdb::Transaction> cfg_txn{env->begin_ro_transaction()};
    auto chain_config{db::read_chain_config(*cfg_txn)};
    if (!chain_config) {
        throw std::runtime_error("Unable to retrieve chain config");
    }
    cfg_txn.release();

    AnalysisCache analysis_cache;
    ExecutionStatePool state_pool;

    uint64_t block_num{from};
    for (; block_num < to; ++block_num) {
        std::unique_ptr<lmdb::Transaction> txn{env->begin_ro_transaction()};

        std::optional<BlockWithHash> bh{db::read_block(*txn, block_num, /*read_senders=*/true)};
        if (!bh) {
            break;
        }

        db::Buffer buffer{txn.get(), block_num};

        ValidationResult err{execute_block(bh->block, buffer, *chain_config, &analysis_cache, &state_pool).second};
        if (err != ValidationResult::kOk) {
            std::cerr << "Failed to execute block " << block_num << "\n";
            continue;
        }

        db::AccountChanges db_account_changes{db::read_account_changes(*txn, block_num)};
        const db::AccountChanges& calculated_account_changes{buffer.account_changes().at(block_num)};
        if (calculated_account_changes != db_account_changes) {
            bool mismatch{false};

            for (const auto& e : db_account_changes) {
                if (!calculated_account_changes.contains(e.first)) {
                    if (!kPhantomAccounts.contains(e.first)) {
                        std::cerr << to_hex(e.first) << " is missing\n";
                        mismatch = true;
                    }
                } else if (Bytes val{calculated_account_changes.at(e.first)}; val != e.second) {
                    std::cerr << "Value mismatch for " << to_hex(e.first) << ":\n";
                    std::cerr << to_hex(val) << "\n";
                    std::cerr << "vs DB\n";
                    std::cerr << to_hex(e.second) << "\n";
                    mismatch = true;
                }
            }
            for (const auto& e : calculated_account_changes) {
                if (!db_account_changes.contains(e.first)) {
                    std::cerr << to_hex(e.first) << " is not in DB\n";
                    mismatch = true;
                }
            }

            if (mismatch) {
                std::cerr << "Account change mismatch for block " << block_num << " 😲\n";
            }
        }

        db::StorageChanges db_storage_changes{db::read_storage_changes(*txn, block_num)};
        db::StorageChanges calculated_storage_changes{};
        if (buffer.storage_changes().contains(block_num)) {
            calculated_storage_changes = buffer.storage_changes().at(block_num);
        }
        if (calculated_storage_changes != db_storage_changes) {
            std::cerr << "Storage change mismatch for block " << block_num << " 😲\n";
            print_storage_changes(calculated_storage_changes);
            std::cout << "vs\n";
            print_storage_changes(db_storage_changes);
        }

        if (block_num % 1000 == 0) {
            absl::Time t2{absl::Now()};
            std::cout << t2 << " Checked blocks ≤ " << block_num << " in " << absl::ToDoubleSeconds(t2 - t1) << " s"
                      << std::endl;
            t1 = t2;
        }
    }

    t1 = absl::Now();
    std::cout << t1 << " Blocks [" << from << "; " << block_num << ") have been checked\n";
    return 0;
}
