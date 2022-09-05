/*
   Copyright 2022 The Silkworm Authors

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
#include <absl/container/flat_hash_set.h>

#include <silkworm/common/directories.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/buffer.hpp>
#include <silkworm/execution/processor.hpp>

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

    std::string chaindata{DataDirectory{}.chaindata().path().string()};
    app.add_option("--chaindata", chaindata, "Path to a database populated by Erigon")
        ->capture_default_str()
        ->check(CLI::ExistingDirectory);

    uint64_t from{1};
    app.add_option("--from", from, "start from block number (inclusive)");

    uint64_t to{UINT64_MAX};
    app.add_option("--to", to, "check up to block number (exclusive)");

    CLI11_PARSE(app, argc, argv);

    absl::Time t1{absl::Now()};

    log::Info() << " Checking change sets in " << chaindata << "\n";

    uint64_t block_num{from};

    try {
        auto data_dir{DataDirectory::from_chaindata(chaindata)};
        data_dir.deploy();
        db::EnvConfig db_config{data_dir.chaindata().path().string()};
        auto env{db::open_env(db_config)};
        auto txn{env.start_read()};
        auto chain_config{db::read_chain_config(txn)};
        if (!chain_config.has_value()) {
            throw std::runtime_error("Unable to retrieve chain config");
        }

        AdvancedAnalysisCache analysis_cache;
        ObjectPool<EvmoneExecutionState> state_pool;
        std::vector<Receipt> receipts;
        auto engine{consensus::engine_factory(chain_config.value())};
        Block block;
        for (; block_num < to; ++block_num) {
            txn.renew_reading();
            if (!db::read_block_by_number(txn, block_num, /*read_senders=*/true, block)) {
                break;
            }

            db::Buffer buffer{txn, /*prune_history_threshold=*/0, /*historical_block=*/block_num};

            ExecutionProcessor processor{block, *engine, buffer, *chain_config};
            processor.evm().advanced_analysis_cache = &analysis_cache;
            processor.evm().state_pool = &state_pool;

            if (const auto res{processor.execute_and_write_block(receipts)}; res != ValidationResult::kOk) {
                log::Error() << "Failed to execute block " << block_num;
                continue;
            }

            db::AccountChanges db_account_changes{db::read_account_changes(txn, block_num)};
            const db::AccountChanges& calculated_account_changes{buffer.account_changes().at(block_num)};
            if (calculated_account_changes != db_account_changes) {
                bool mismatch{false};

                for (const auto& e : db_account_changes) {
                    if (!calculated_account_changes.contains(e.first)) {
                        if (!kPhantomAccounts.contains(e.first)) {
                            log::Error() << to_hex(e.first) << " is missing";
                            mismatch = true;
                        }
                    } else if (Bytes val{calculated_account_changes.at(e.first)}; val != e.second) {
                        log::Error() << "Value mismatch for " << to_hex(e.first) << ":\n"
                                     << to_hex(val) << "\n"
                                     << "vs DB\n"
                                     << to_hex(e.second);
                        mismatch = true;
                    }
                }
                for (const auto& e : calculated_account_changes) {
                    if (!db_account_changes.contains(e.first)) {
                        log::Error() << to_hex(e.first) << " is not in DB";
                        mismatch = true;
                    }
                }

                if (mismatch) {
                    log::Error() << "Account change mismatch for block " << block_num << " 😲";
                }
            }

            db::StorageChanges db_storage_changes{db::read_storage_changes(txn, block_num)};
            db::StorageChanges calculated_storage_changes{};
            if (buffer.storage_changes().contains(block_num)) {
                calculated_storage_changes = buffer.storage_changes().at(block_num);
            }
            if (calculated_storage_changes != db_storage_changes) {
                log::Error() << "Storage change mismatch for block " << block_num << " 😲";
                print_storage_changes(calculated_storage_changes);
                std::cout << "vs\n";
                print_storage_changes(db_storage_changes);
            }

            if (block_num % 1000 == 0) {
                absl::Time t2{absl::Now()};
                log::Info() << " Checked blocks ≤ " << block_num << " in " << absl::ToDoubleSeconds(t2 - t1) << " s";
                t1 = t2;
            }
        }
    } catch (const std::exception& ex) {
        log::Error() << ex.what();
        return -5;
    }

    log::Info() << " Blocks [" << from << "; " << block_num << ") have been checked";
    return 0;
}
