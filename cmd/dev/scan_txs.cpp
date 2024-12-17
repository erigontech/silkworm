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

#include <iostream>
#include <stdexcept>

#include <CLI/CLI.hpp>

#include <silkworm/core/execution/execution.hpp>
#include <silkworm/core/protocol/rule_set.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/buffer.hpp>
#include <silkworm/infra/common/directories.hpp>

int main(int argc, char* argv[]) {
    CLI::App app{"Executes Ethereum blocks and scans txs for errored txs"};
    using namespace silkworm;

    std::string chaindata{DataDirectory{}.chaindata().path().string()};
    app.add_option("--chaindata", chaindata, "Path to a database populated by Erigon")
        ->capture_default_str()
        ->check(CLI::ExistingDirectory);

    uint64_t from{1};
    app.add_option("--from", from, "start from block number (inclusive)");

    uint64_t to{UINT64_MAX};
    app.add_option("--to", to, "check up to block number (exclusive)");

    CLI11_PARSE(app, argc, argv)

    if (from > to) {
        std::cerr << "--from (" << from << ") must be less than or equal to --to (" << to << ").\n";
        return -1;
    }

    int rv{0};

    // Note: If Erigon is actively syncing its database (syncing), it is important not to create
    // long-running database reads transactions even though that may make your processing faster.
    // Uncomment the following line (and comment the line below) only if you're certain Erigon is not
    // running on the same machine.
    // std::unique_ptr<lmdb::Transaction> txn{env->begin_ro_transaction()};

    AnalysisCache analysis_cache{/*max_size=*/5'000};
    std::vector<Receipt> receipts;

    try {
        auto data_dir{DataDirectory::from_chaindata(chaindata)};
        data_dir.deploy();
        datastore::kvdb::EnvConfig db_config{data_dir.chaindata().path().string()};
        auto env{datastore::kvdb::open_env(db_config)};
        datastore::kvdb::RWTxnManaged txn{env};
        auto chain_config{db::read_chain_config(txn)};
        if (!chain_config) {
            throw std::runtime_error("Unable to retrieve chain config");
        }
        auto rule_set{protocol::rule_set_factory(*chain_config)};
        if (!rule_set) {
            throw std::runtime_error("Unable to retrieve protocol rule set");
        }

        // counters
        uint64_t n_txs{0}, n_errors{0};

        Block block;
        for (uint64_t block_num{from}; block_num < to; ++block_num) {
            // Note: See the comment above. You may uncomment that line and comment the next line if you're certain
            // that Erigon is not syncing on the same machine. If you use a long-running transaction by doing this, and
            // you're mistaken (Erigon is syncing), the database file may 'grow quickly' as per the LMDB docs.
            txn->renew_reading();

            // Read the block
            if (!db::read_block_by_number(txn, block_num, /*read_senders=*/true, block)) {
                break;
            }

            db::Buffer buffer{txn, std::make_unique<db::BufferROTxDataModel>(txn)};
            buffer.set_historical_block(block_num);

            ExecutionProcessor processor{block, *rule_set, buffer, *chain_config, true};
            processor.evm().analysis_cache = &analysis_cache;

            // Execute the block and retrieve the receipts
            if (const ValidationResult res = processor.execute_block(receipts); res != ValidationResult::kOk) {
                std::cerr << "Validation error " << static_cast<int>(res) << " at block " << block_num << "\n";
            }

            processor.flush_state();

            // There is one receipt per transaction
            SILKWORM_ASSERT(block.transactions.size() == receipts.size());

            // Erigon returns success in the receipt even for pre-Byzantium txs.
            for (const auto& receipt : receipts) {
                ++n_txs;
                n_errors += (!receipt.success);
            }

            // Report and reset counters
            if ((block_num % 50000) == 0) {
                std::cout << block_num << "," << n_txs << "," << n_errors << "\n";
                n_txs = n_errors = 0;

            } else if ((block_num % 100) == 0) {
                // report progress
                std::cerr << block_num << "\r";
                std::cerr.flush();
            }

            // Note: If per-block database transaction (txn) is being used, it will go out of scope here
            // and will be reset. No need to explicitly clean up here.
        }

    } catch (std::exception& ex) {
        std::cout << ex.what() << "\n";
        rv = -1;
    }

    return rv;
}
