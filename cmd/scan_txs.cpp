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

#include <CLI/CLI.hpp>

#include <silkworm/common/directories.hpp>
#include <silkworm/consensus/engine.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/buffer.hpp>
#include <silkworm/execution/execution.hpp>

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

    CLI11_PARSE(app, argc, argv);

    if (from > to) {
        std::cerr << "--from (" << from << ") must be less than or equal to --to (" << to << ").\n";
        return -1;
    }

    int retvar{0};

    // Note: If Erigon is actively syncing its database (syncing), it is important not to create
    // long-running datbase reads transactions even though that may make your processing faster.
    // Uncomment the following line (and comment the line below) only if you're certain Erigon is not
    // running on the same machine.
    // std::unique_ptr<lmdb::Transaction> txn{env->begin_ro_transaction()};

    AdvancedAnalysisCache analysis_cache;
    ObjectPool<EvmoneExecutionState> state_pool;
    std::vector<Receipt> receipts;

    try {
        auto data_dir{DataDirectory::from_chaindata(chaindata)};
        data_dir.deploy();
        db::EnvConfig db_config{data_dir.chaindata().path().string()};
        auto env{db::open_env(db_config)};
        auto txn{env.start_read()};
        auto chain_config{db::read_chain_config(txn)};
        if (!chain_config) {
            throw std::runtime_error("Unable to retrieve chain config");
        }
        auto engine{consensus::engine_factory(chain_config.value())};
        if (!engine) {
            throw std::runtime_error("Unable to retrieve consensus engine");
        }

        // counters
        uint64_t nTxs{0}, nErrors{0};

        Block block;
        for (uint64_t block_num{from}; block_num < to; ++block_num) {
            // Note: See the comment above. You may uncomment that line and comment the next line if you're certain
            // that Erigon is not syncing on the same machine. If you use a long-running transaction by doing this, and
            // you're mistaken (Erigon is syncing), the database file may 'grow quickly' as per the LMDB docs.
            txn.renew_reading();

            // Read the block
            if (!db::read_block_by_number(txn, block_num, /*read_senders=*/true, block)) {
                break;
            }

            db::Buffer buffer{txn, /*prune_history_threshold=*/0, /*historical_block=*/block_num};

            ExecutionProcessor processor{block, *engine, buffer, *chain_config};
            processor.evm().advanced_analysis_cache = &analysis_cache;
            processor.evm().state_pool = &state_pool;

            // Execute the block and retrieve the receipts
            if (const auto res{processor.execute_and_write_block(receipts)}; res != ValidationResult::kOk) {
                std::cerr << "Validation error " << static_cast<int>(res) << " at block " << block_num << "\n";
            }

            // There is one receipt per transaction
            assert(block.transactions.size() == receipts.size());

            // Erigon returns success in the receipt even for pre-Byzantium txs.
            for (const auto& receipt : receipts) {
                ++nTxs;
                nErrors += (!receipt.success);
            }

            // Report and reset counters
            if ((block_num % 50000) == 0) {
                std::cout << block_num << "," << nTxs << "," << nErrors << std::endl;
                nTxs = nErrors = 0;

            } else if ((block_num % 100) == 0) {
                // report progress
                std::cerr << block_num << "\r";
                std::cerr.flush();
            }

            // Note: If per-block database transaction (txn) is being used, it will go out of scope here
            // and will be reset. No need to explicitly clean up here.
        }

    } catch (std::exception& ex) {
        std::cout << ex.what() << std::endl;
        retvar = -1;
    }

    return retvar;
}
