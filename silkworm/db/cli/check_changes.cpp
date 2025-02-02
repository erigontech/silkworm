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

#include <stdexcept>

#include <CLI/CLI.hpp>
#include <absl/container/flat_hash_set.h>
#include <magic_enum.hpp>

#include <silkworm/core/execution/processor.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/buffer.hpp>
#include <silkworm/db/data_store.hpp>
#include <silkworm/db/datastore/snapshots/snapshot_repository.hpp>
#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/signal_handler.hpp>

using namespace evmc::literals;
using namespace silkworm;

// Non-existing accounts only touched by zero-value internal transactions:
// e.g. https://etherscan.io/address/0x000000000000000000636f6e736f6c652e6c6f67
static const absl::flat_hash_set<evmc::address> kPhantomAccounts{
    0x000000000000000000636f6e736f6c652e6c6f67_address,
    0x2386f26fc10000b4e16d0168e52d35cacd2c6185_address,
    0x5a719cf3e02c17c876f6d294adb5cb7c6eb47e2f_address,
};

static void print_storage_locations(const db::ChangedLocations& changed_locations) {
    std::cout << "storage:\n";
    for (const auto& [location, value] : changed_locations) {
        std::cout << "\t" << to_hex(location) << " = " << to_hex(value) << "\n";
    }
}

static void print_storage_incarnations(const db::ChangedIncarnations& changed_incarnations) {
    for (const auto& [incarnation, changed_locations] : changed_incarnations) {
        std::cout << "incarnation: " << incarnation << "\n";
        print_storage_locations(changed_locations);
    }
}

static void print_storage_changes(const evmc::address& address, const db::ChangedIncarnations& changed_incarnations) {
    std::cout << "address: " << address << "\n";
    print_storage_incarnations(changed_incarnations);
}

static void print_all_storage_changes(const db::StorageChanges& s) {
    for (const auto& [address, changed_incarnations] : s) {
        print_storage_changes(address, changed_incarnations);
    }
}

int main(int argc, char* argv[]) {
    SignalHandler::init();

    CLI::App app{"Execute Ethereum blocks and compare resulting state changes against db"};

    std::string chaindata{DataDirectory{}.chaindata().path().string()};
    app.add_option("--chaindata", chaindata, "Path to a database populated by Erigon")
        ->capture_default_str()
        ->check(CLI::ExistingDirectory);

    BlockNum from{1};
    app.add_option("--from", from, "Start from block number (inclusive)");

    BlockNum to{UINT64_MAX};
    app.add_option("--to", to, "Check up to block number (inclusive)");

    bool full_mismatch_dump{false};
    app.add_flag("--full_mismatch_dump", full_mismatch_dump, "Generate full dump on mismatch")
        ->capture_default_str();

    bool continue_after_mismatch{false};
    app.add_flag("--continue_after_mismatch", continue_after_mismatch, "Continue to compare after first mismatch")
        ->capture_default_str();

    CLI11_PARSE(app, argc, argv)

    BlockNum block_num{from};
    try {
        ensure(from > 0, "Invalid input: from must be greater than zero");

        absl::Time t1{absl::Now()};
        SILK_INFO << "Checking state change sets in " << chaindata;

        auto data_dir{DataDirectory::from_chaindata(chaindata)};
        data_dir.deploy();
        datastore::kvdb::EnvConfig db_config{data_dir.chaindata().path().string()};

        db::DataStore data_store{
            db_config,
            data_dir.snapshots().path(),
        };

        auto txn = data_store.chaindata().access_rw().start_rw_tx();
        auto chain_config{db::read_chain_config(txn)};
        if (!chain_config) {
            throw std::runtime_error("Unable to retrieve chain config");
        }

        db::DataModel access_layer = db::DataModelFactory{data_store.ref()}(txn);

        AnalysisCache analysis_cache{/*max_size=*/5'000};
        std::vector<Receipt> receipts;
        auto rule_set{protocol::rule_set_factory(*chain_config)};
        Block block;
        for (; block_num <= to; ++block_num) {
            SILK_TRACE << "Processing block " << block_num;
            if (!access_layer.read_block(block_num, /*read_senders=*/true, block)) {
                SILK_ERROR << "Failed reading block " << block_num;
                break;
            }

            db::Buffer buffer{txn, std::make_unique<db::BufferFullDataModel>(access_layer)};
            buffer.set_historical_block(block_num);

            ExecutionProcessor processor{block, *rule_set, buffer, *chain_config, true};
            processor.evm().analysis_cache = &analysis_cache;

            if (const ValidationResult res = processor.execute_block(receipts); res != ValidationResult::kOk) {
                SILK_ERROR << "Failed execution for block " << block_num << " result " << magic_enum::enum_name<>(res);
                continue;
            }

            processor.flush_state();

            db::AccountChanges db_account_changes{db::read_account_changes(txn, block_num)};

            const auto& block_account_changes{buffer.account_changes()};
            if (block_account_changes.contains(block_num)) {
                const db::AccountChanges& calculated_account_changes{block_account_changes.at(block_num)};
                if (calculated_account_changes != db_account_changes) {
                    bool mismatch{false};

                    for (const auto& e : db_account_changes) {
                        SILK_INFO << "key=" << to_hex(e.first.bytes) << " value=" << to_hex(e.second);
                        if (!calculated_account_changes.contains(e.first)) {
                            if (!kPhantomAccounts.contains(e.first)) {
                                SILK_ERROR << e.first << " is missing";
                                mismatch = true;
                            } else {
                                SILK_WARN << "Phantom account " << e.first << " skipped";
                            }
                        } else if (Bytes val{calculated_account_changes.at(e.first)}; val != e.second) {
                            SILK_ERROR
                                << "Value mismatch for " << e.first << ":\n"
                                << to_hex(val) << "\n"
                                << "vs DB\n"
                                << to_hex(e.second);
                            mismatch = true;
                        }
                    }
                    for (const auto& e : calculated_account_changes) {
                        if (!db_account_changes.contains(e.first)) {
                            SILK_ERROR << e.first << " is not in DB";
                            mismatch = true;
                        }
                    }

                    if (mismatch) {
                        SILK_ERROR << "Account change mismatch for block " << block_num << " 😲";
                    }
                }
            } else {
                ensure(db_account_changes.empty(), "read account changes are not empty whilst calculated ones are");
            }

            db::StorageChanges db_storage_changes{db::read_storage_changes(txn, block_num)};
            db::StorageChanges calculated_storage_changes{};
            if (buffer.storage_changes().contains(block_num)) {
                calculated_storage_changes = buffer.storage_changes().at(block_num);
            }
            if (calculated_storage_changes != db_storage_changes) {
                SILK_ERROR << "Storage change mismatch for block " << block_num << " 😲";
                if (full_mismatch_dump) {
                    std::cout << "calculated storage changes:\n";
                    print_all_storage_changes(calculated_storage_changes);
                    std::cout << "vs\ndb storage changes:\n";
                    print_all_storage_changes(db_storage_changes);
                }
                int mismatch_count{0};
                auto calculated_it{calculated_storage_changes.cbegin()};
                auto db_it{db_storage_changes.cbegin()};
                for (; calculated_it != calculated_storage_changes.cend() && db_it != db_storage_changes.cend(); ++calculated_it, ++db_it) {
                    const auto& calculated_change{*calculated_it};
                    const auto& stored_change{*db_it};
                    if (calculated_change != stored_change) {
                        std::cout << "Mismatch number " << mismatch_count + 1 << ") is:\n- calculated change:\n";
                        print_storage_changes(calculated_change.first, calculated_change.second);
                        std::cout << "- stored change:\n";
                        print_storage_changes(stored_change.first, stored_change.second);
                        ++mismatch_count;
                        if (!continue_after_mismatch) {
                            SILK_INFO << "Use flag --continue_after_mismatch to see all mismatches for block " << block_num;
                            break;
                        }
                    }
                }
                if (continue_after_mismatch) {
                    SILK_ERROR << "Total mismatch count is " << mismatch_count << " for block " << block_num;
                }
            }

            if (SignalHandler::signalled()) {
                break;
            }

            if (block_num % 100'000 == 0) {
                absl::Time t2{absl::Now()};
                SILK_INFO << "Checked blocks up to " << block_num << " in " << absl::ToDoubleSeconds(t2 - t1) << " s";
                t1 = t2;
            }
        }
    } catch (const std::exception& ex) {
        SILK_ERROR << ex.what();
        return -5;
    }

    SILK_INFO << "State changes for blocks [" << from << "; " << block_num - 1 << "] have been checked";
    return 0;
}
