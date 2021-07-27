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

#include <atomic>
#include <csignal>
#include <filesystem>
#include <queue>
#include <string>
#include <thread>

#include <CLI/CLI.hpp>
#include <boost/endian.hpp>
#include <boost/format.hpp>
#include <boost/interprocess/mapped_region.hpp>
#include <boost/signals2.hpp>
#include <ethash/keccak.hpp>
#include <magic_enum.hpp>

#include <silkworm/chain/config.hpp>
#include <silkworm/common/data_dir.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/common/worker.hpp>
#include <silkworm/crypto/ecdsa.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/mdbx.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/etl/collector.hpp>
#include <silkworm/stagedsync/recovery/recovery_farm.hpp>
#include <silkworm/types/block.hpp>

using namespace silkworm;

std::unique_ptr<stagedsync::recovery::RecoveryFarm> farm;

void sig_handler(int) {
    std::cout << std::endl << " Got interrupt. Stopping ..." << std::endl << std::endl;
    if (farm) {
        farm->stop();
    }
}

struct app_options_t {
    std::string datadir{};  // Provided database path
    uint32_t max_workers{std::thread::hardware_concurrency() -
                         1};        // Max number of threads (1 thread is reserved for main)
    size_t batch_size{1'000'000};   // Number of work packages to serve a worker
    uint32_t block_from{1u};        // Initial block number to start from
    uint32_t block_to{UINT32_MAX};  // Final block number to process
    bool dry{false};                // Runs in dry mode (no data is persisted on disk)
    bool debug{false};              // Whether to display some debug info
};

int main(int argc, char* argv[]) {
    namespace fs = std::filesystem;
    // Init command line parser
    CLI::App app("Senders recovery tool.");
    app_options_t options{};
    options.datadir = DataDirectory{}.get_chaindata_path().string();  // Default chain data db path

    // Command line arguments
    app.add_option("--chaindata", options.datadir, "Path to chain db", true)->check(CLI::ExistingDirectory);

    app.add_option("--workers", options.max_workers, "Max number of worker threads", true)
        ->check(CLI::Range(1u, std::max(1u, std::thread::hardware_concurrency() - 1)));

    app.add_option("--from", options.block_from, "Initial block number to process (inclusive)", true)
        ->check(CLI::Range(1u, UINT32_MAX));
    app.add_option("--to", options.block_to, "Final block number to process (inclusive)", true)
        ->check(CLI::Range(1u, UINT32_MAX));

    app.add_option("--batch", options.batch_size, "Number of transactions to process per batch", true)
        ->check(CLI::Range(1'000u, 10'000'000u));

    app.add_flag("--debug", options.debug, "May print some debug/trace info.");
    app.add_flag("--dry", options.dry, "Runs the full cycle but nothing is persisted");

    app.require_subcommand(1);  // One of the following subcommands is required
    auto& app_recover = *app.add_subcommand("recover", "Recovers Senders' addresses");
    auto& app_unwind = *app.add_subcommand("unwind", "Unwinds Senders' stage to given height");

    CLI11_PARSE(app, argc, argv);

    if (options.debug) {
        SILKWORM_LOG_VERBOSITY(LogLevel::Debug);
    }

    if (!options.block_from) options.block_from = 1u;  // Block 0 (genesis) has no transactions

    // Invoke proper action
    int rc{0};
    try {
        if (!app_recover && !app_unwind) {
            throw std::runtime_error("Invalid operation");
        }

        // Set database parameters
        DataDirectory data_dir{DataDirectory::from_chaindata(options.datadir)};
        data_dir.create_tree();

        db::EnvConfig db_config{data_dir.get_chaindata_path().string()};
        etl::Collector collector(data_dir.get_etl_path().string().c_str(), /* flush size */ 512 * kMebi);

        // Open db and transaction
        auto env{db::open_env(db_config)};
        auto txn{env.start_write()};

        // Create farm instance and do work
        farm = std::make_unique<stagedsync::recovery::RecoveryFarm>(txn, options.max_workers, options.batch_size,
                                                                    collector);
        stagedsync::StageResult result{stagedsync::StageResult::kSuccess};

        signal(SIGINT, sig_handler);
        signal(SIGTERM, sig_handler);

        if (app_recover) {
            result = farm->recover(options.block_from, options.block_to);
        } else {
            result = farm->unwind(options.block_from);
        }

        if (rc = static_cast<int>(result), rc) {
            SILKWORM_LOG(LogLevel::Error)
                << (app_recover ? "Recovery" : "Unwind") << " returned " << magic_enum::enum_name(result) << std::endl;
        } else {
            if (!options.dry) {
                SILKWORM_LOG(LogLevel::Info) << "Committing" << std::endl;
                txn.commit();
            } else {
                SILKWORM_LOG(LogLevel::Info) << "Not committing (--dry)" << std::endl;
            }
        }

    } catch (const std::exception& ex) {
        SILKWORM_LOG(LogLevel::Error) << ex.what() << std::endl;
        return -1;
    }

    return rc;
}
