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
#include <chrono>
#include <iostream>
#include <string>
#include <thread>

#include <CLI/CLI.hpp>
#include <node/silkworm/downloader/internals/header_retrieval.hpp>

#include <silkworm/common/directories.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/downloader/block_provider.hpp>
#include <silkworm/downloader/sentry_client.hpp>

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

    app.add_option("--chaindata", db_path, "Path to the chain database", true)
        ->check(CLI::ExistingDirectory);
    app.add_option("--chain", chain_name, "Network name", true)
        ->needs("--chaindata");
    app.add_option("-s,--sentryaddr", sentry_addr, "address:port of sentry", true);
        //  todo ->check?
    app.add_option("-f,--filesdir", temporary_file_path, "Path to a temp files dir", true)
        ->check(CLI::ExistingDirectory);

    CLI11_PARSE(app, argc, argv);

    SILKWORM_LOG_VERBOSITY(LogLevel::Trace);

    std::thread block_request_processing;
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
        DbTx db{db_path};

        // Node current status
        HeaderRetrieval headers(db);
        auto [head_hash, head_td] = headers.head_hash_and_total_difficulty();
        cout << "   head_hash = " << head_hash.to_hex() << "\n";
        cout << "   head_td   = " << intx::to_string(head_td) << "\n\n" << std::flush;

        // Sentry client - connects to sentry
        SentryClient sentry{sentry_addr};

        // Block provider - provides headers and bodies to external peers
        BlockProvider block_provider{sentry, db, chain_identity};
        block_request_processing = std::thread( [&block_provider]() {  // todo: join in block_provider destructor
            block_provider.execution_loop();
        });

        // Stage1 - Header downloader - example code
        //BlockNum target_block = 13'000'000; // only for test
        //HeaderDownloader header_downloader{sentry, db, chain_identity};
        //header_downloader.wind(target_block);

        // Wait for user termination request
        std::cin.get();         // wait for user press "enter"
        block_provider.stop();  // signal exiting
    }
    catch(std::exception& e) {
        cerr << "Exception: " << e.what() << "\n";
        return_value = 1;
    }

    if (block_request_processing.joinable())
        block_request_processing.join(); // wait thread termination
    return return_value;
}
