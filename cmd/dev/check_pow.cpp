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

#include <filesystem>
#include <stdexcept>
#include <string>

#include <CLI/CLI.hpp>
#include <ethash/ethash.hpp>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/common/stopwatch.hpp>
#include <silkworm/infra/concurrency/signal_handler.hpp>
#include <silkworm/node/db/access_layer.hpp>
#include <silkworm/node/db/stages.hpp>

namespace fs = std::filesystem;
using namespace silkworm;

struct app_options_t {
    std::string datadir{};          // Provided database path
    uint32_t block_from{1u};        // Initial block number to start from
    uint32_t block_to{UINT32_MAX};  // Final block number to process
    bool debug{false};              // Whether to display some debug info
};

int main(int argc, char* argv[]) {
    // Init command line parser
    CLI::App app("Check PoW.");
    app_options_t options{};
    options.datadir = DataDirectory{}.chaindata().path().string();  // Default chain data db path

    // Command line arguments
    app.add_option("--chaindata", options.datadir, "Path to chain db")
        ->capture_default_str()
        ->check(CLI::ExistingDirectory);

    app.add_option("--from", options.block_from, "Initial block number to process (inclusive)")
        ->capture_default_str()
        ->check(CLI::Range(1u, UINT32_MAX));
    app.add_option("--to", options.block_to, "Final block number to process (inclusive)")
        ->capture_default_str()
        ->check(CLI::Range(1u, UINT32_MAX));

    app.add_flag("--debug", options.debug, "May print some debug/trace info.");

    CLI11_PARSE(app, argc, argv)

    if (options.debug) {
        log::set_verbosity(log::Level::kDebug);
    }

    if (!options.block_from) options.block_from = 1u;  // Block 0 (genesis) has no transactions

    SignalHandler::init();

    // Invoke proper action
    int rc{0};
    try {
        auto data_dir{DataDirectory::from_chaindata(options.datadir)};
        data_dir.deploy();
        options.datadir = data_dir.chaindata().path().string();

        // Set database parameters
        db::EnvConfig db_config{options.datadir};
        auto env{db::open_env(db_config)};
        db::ROTxnManaged txn{env};

        auto config{db::read_chain_config(txn)};
        if (!config.has_value()) {
            throw std::runtime_error("Invalid chain config");
        }
        if (!std::holds_alternative<protocol::EthashConfig>(config->rule_set_config)) {
            throw std::runtime_error("Not an Ethash PoW chain");
        }

        auto max_headers_height{db::stages::read_stage_progress(txn, db::stages::kSendersKey)};
        options.block_to = std::min(options.block_to, static_cast<uint32_t>(max_headers_height));

        // Initialize epoch
        auto epoch_num{options.block_from / ethash::epoch_length};
        log::Info() << "Initializing Light Cache for DAG epoch " << epoch_num;
        auto epoch_context{ethash::create_epoch_context(static_cast<int>(epoch_num))};

        auto canonical_hashes{db::open_cursor(txn, db::table::kCanonicalHashes)};

        // Loop blocks
        StopWatch sw;
        sw.start();
        for (uint32_t block_num{options.block_from}; block_num <= options.block_to && !SignalHandler::signalled();
             block_num++) {
            if (epoch_context->epoch_number != static_cast<int>(block_num / ethash::epoch_length)) {
                epoch_num = (block_num / ethash::epoch_length);
                log::Info() << "Initializing Light Cache for DAG epoch " << epoch_num;
                epoch_context = ethash::create_epoch_context(static_cast<int>(epoch_num));
            }

            auto block_key{db::block_key(block_num)};
            auto data{canonical_hashes.find(db::to_slice(block_key), /*throw_notfound*/ false)};
            if (!data) {
                throw std::runtime_error("Can't retrieve canonical hash for block " + std::to_string(block_num));
            }

            auto header_key{to_bytes32(db::from_slice(data.value))};
            auto header{db::read_header(txn, block_num, header_key.bytes)};
            if (!header.has_value()) {
                throw std::runtime_error("Can't retrieve header for block " + std::to_string(block_num));
            }

            // Verify Proof of Work
            uint64_t nonce{endian::load_big_u64(header->nonce.data())};

            auto seal_hash(header->hash(/*for_sealing =*/true));
            const auto diff256{intx::be::store<ethash::hash256>(header->difficulty)};
            const auto sealh256{ethash::hash256_from_bytes(seal_hash.bytes)};
            const auto mixh256{ethash::hash256_from_bytes(header->prev_randao.bytes)};
            if (const auto ec = ethash::verify_against_difficulty(*epoch_context, sealh256, mixh256, nonce, diff256);
                ec) {
                auto boundary256{header->boundary()};
                auto result{ethash::hash(*epoch_context, sealh256, nonce)};
                auto b{to_bytes32({boundary256.bytes, 32})};
                auto f{to_bytes32({result.final_hash.bytes, 32})};
                auto m{to_bytes32({result.mix_hash.bytes, 32})};

                std::cout << "\n Pow Verification error on block " << block_num << " : \n"
                          << "Error: " << ec << "\n"
                          << "Final hash " << to_hex(f) << " expected below " << to_hex(b) << "\n"
                          << "Mix   hash " << to_hex(m) << " expected mix " << to_hex(m) << "\n";
                break;
            }

            if (!(block_num % 1000)) {
                const auto interval{sw.lap()};
                log::Info() << "At block height " << block_num << " in " << StopWatch::format(interval.second);
            }
        }

        log::Info() << "Complete !";

    } catch (const fs::filesystem_error& ex) {
        log::Error() << ex.what() << " Check your filesystem permissions";
    } catch (const std::exception& ex) {
        log::Error() << ex.what();
    }

    return rc;
}
