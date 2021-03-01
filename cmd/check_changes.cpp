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

#include <absl/container/flat_hash_set.h>
#include <absl/flags/flag.h>
#include <absl/flags/parse.h>
#include <absl/flags/usage.h>
#include <absl/time/time.h>

#include <boost/filesystem.hpp>
#include <iostream>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/buffer.hpp>
#include <silkworm/execution/execution.hpp>

using namespace evmc::literals;

// Non-existing accounts only touched by zero-value internal transactions:
// e.g. https://etherscan.io/address/0x000000000000000000636f6e736f6c652e6c6f67
static const absl::flat_hash_set<evmc::address> kPhantomAccounts{
    0x000000000000000000636f6e736f6c652e6c6f67_address,
    0x2386f26fc10000b4e16d0168e52d35cacd2c6185_address,
    0x5a719cf3e02c17c876f6d294adb5cb7c6eb47e2f_address,
};

ABSL_FLAG(std::string, datadir, silkworm::db::default_path(), "chain DB path");
ABSL_FLAG(uint64_t, from, 1, "start from block number (inclusive)");
ABSL_FLAG(uint64_t, to, UINT64_MAX, "check up to block number (exclusive)");

int main(int argc, char* argv[]) {
    absl::SetProgramUsageMessage("Executes Ethereum blocks and compares resulting change sets against DB.");
    absl::ParseCommandLine(argc, argv);

    namespace fs = boost::filesystem;

    fs::path db_path(absl::GetFlag(FLAGS_datadir));
    if (!fs::exists(db_path) || !fs::is_directory(db_path) || db_path.empty()) {
        std::cerr << absl::GetFlag(FLAGS_datadir) << " does not exist.\n";
        std::cerr << "Use --datadir flag to point to a Turbo-Geth populated chaindata folder.\n";
        return -1;
    }

    absl::Time t1{absl::Now()};
    std::cout << t1 << " Checking change sets in " << absl::GetFlag(FLAGS_datadir) << "\n";

    using namespace silkworm;

    lmdb::DatabaseConfig db_config{absl::GetFlag(FLAGS_datadir)};
    std::shared_ptr<lmdb::Environment> env{lmdb::get_env(db_config)};

    const uint64_t from{absl::GetFlag(FLAGS_from)};
    const uint64_t to{absl::GetFlag(FLAGS_to)};

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

        ValidationResult err{execute_block(bh->block, buffer, kMainnetConfig, &analysis_cache, &state_pool).second};
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
