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
#include <string>
#include <thread>

#include <CLI/CLI.hpp>

#include <silkworm/common/directories.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/downloader/internals/header_retrieval.hpp>
#include <silkworm/downloader/stage_headers.hpp>
#include "silkworm/downloader/stage_bodies.hpp"

using namespace silkworm;

// Main
int main(int argc, char* argv[]) {
    using std::string, std::cout, std::cerr, std::optional;
    using namespace std::chrono;

    // Command line parsing
    CLI::App app{"Download Headers. Connect to p2p sentry and start header downloading process (stage 1)"};

    string chain_name = ChainIdentity::mainnet.name;
    string db_path = DataDirectory{}.chaindata().path().string();
    string temporary_file_path = ".";
    string sentry_addr = "127.0.0.1:9091";

    log::Settings settings;
    settings.log_threads = true;
    settings.log_file = "downloader.log";
    settings.log_verbosity = log::Level::kInfo;
    settings.log_thousands_sep = '\'';

    app.add_option("--chaindata", db_path, "Path to the chain database", true)
        ->check(CLI::ExistingDirectory);
    app.add_option("--chain", chain_name, "Network name", true)
        ->needs("--chaindata");
    app.add_option("-s,--sentryaddr", sentry_addr, "address:port of sentry", true);
        //  todo ->check?
    app.add_option("-f,--filesdir", temporary_file_path, "Path to a temp files dir", true)
        ->check(CLI::ExistingDirectory);
    app.add_option("-v,--verbosity", settings.log_verbosity, "Verbosity", true)
        ->check(CLI::Range(static_cast<uint32_t>(log::Level::kCritical), static_cast<uint32_t>(log::Level::kTrace)));

    CLI11_PARSE(app, argc, argv);

    log::init(settings);
    log::Info() << "STARTING";

    int return_value = 0;

    try {
        // EIP-2124 based chain identity scheme (networkId + genesis + forks)
        ChainIdentity chain_identity;
        if (chain_name == ChainIdentity::mainnet.name)
            chain_identity = ChainIdentity::mainnet;
        else if (chain_name == ChainIdentity::goerli.name)
            chain_identity = ChainIdentity::goerli;
        else
            throw std::logic_error(chain_name + " not supported");

        cout << "Download Headers - Silkworm\n"
             << "   chain-id: " << chain_identity.chain.chain_id << "\n"
             << "   genesis-hash: " << chain_identity.genesis_hash << "\n"
             << "   hard-forks: " << chain_identity.distinct_fork_numbers().size() << "\n";

        // Database access
        Db db{db_path};

        // Node current status
        HeaderRetrieval headers(Db::ReadOnlyAccess{db});
        auto [head_hash, head_td] = headers.head_hash_and_total_difficulty();
        auto head_height = headers.head_height();
        cout << "   head hash   = " << head_hash.to_hex() << "\n";
        cout << "   head td     = " << intx::to_string(head_td) << "\n";
        cout << "   head height = " << head_height << "\n\n" << std::flush;

        // Sentry client - connects to sentry
        SentryClient sentry{sentry_addr};
        sentry.set_status(head_hash, head_td, chain_identity);
        sentry.hand_shake();
        auto message_receiving = std::thread([&sentry]() { sentry.execution_loop(); });
        auto stats_receiving = std::thread([&sentry]() { sentry.stats_receiving_loop(); });

        // BlockDownloader - download headers and bodies from remote peers using the sentry
        BlockDownloader block_downloader{sentry, Db::ReadOnlyAccess{db}, chain_identity};
        auto block_downloading = std::thread([&block_downloader]() { block_downloader.execution_loop(); });

        // Stage1 - Header downloader - example code
        bool first_sync = true;  // = starting up silkworm
        HeadersStage header_stage{Db::ReadWriteAccess{db}, block_downloader};
        BodiesStage body_stage{Db::ReadWriteAccess{db}, block_downloader};

        // Sample stage loop with 1 stage
        Stage::Result stage_result{Stage::Result::Unspecified};
        do {
            forward(stages)
            if (stage_result.status != Stage::Result::UnwindNeeded) {
                stage_result = header_stage.forward(first_sync);
            } else {
                stage_result = header_stage.unwind_to(*stage_result.unwind_point, *stage_result.bad_block);
            }
            first_sync = false;
        } while (stage_result.status != Stage::Result::Error);


        // Sample stage loop with 1 stage
        Stage::Result stage_result{Stage::Result::Unspecified};
        do {
            if (stage_result.status != Stage::Result::UnwindNeeded) {
                stage_result = header_stage.forward(first_sync);
            } else {
                stage_result = header_stage.unwind_to(*stage_result.unwind_point, *stage_result.bad_block);
            }
            first_sync = false;
        } while (stage_result.status != Stage::Result::Error);

        // Wait for user termination request
        std::cin.get();            // wait for user press "enter"
        block_downloader.stop();     // signal exiting

        // wait threads termination
        message_receiving.join();
        stats_receiving.join();
        block_downloading.join();
    } catch (std::exception& e) {
        cerr << "Exception: " << e.what() << "\n";
        return_value = 1;
    }

    return return_value;
}
