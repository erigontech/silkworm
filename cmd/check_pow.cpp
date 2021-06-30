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

#include <csignal>
#include <filesystem>
#include <string>

#include <CLI/CLI.hpp>
#include <boost/interprocess/mapped_region.hpp>
#include <ethash/ethash.hpp>
#include <ethash/keccak.hpp>

#include <silkworm/chain/config.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/types/block.hpp>

namespace fs = std::filesystem;
using namespace silkworm;

std::atomic_bool g_should_stop{false};  // Request for stop from user or OS

struct app_options_t {
    std::string datadir{};          // Provided database path
    uint32_t block_from{1u};        // Initial block number to start from
    uint32_t block_to{UINT32_MAX};  // Final block number to process
    bool debug{false};              // Whether to display some debug info
};

void sig_handler(int signum) {
    (void)signum;
    std::cout << std::endl << " Got interrupt. Stopping ..." << std::endl << std::endl;
    g_should_stop.store(true);
}

int main(int argc, char* argv[]) {
    // Init command line parser
    CLI::App app("Check PoW.");
    app_options_t options{};
    options.datadir = db::default_path();  // Default chain data db path

    // Command line arguments
    app.add_option("--chaindata", options.datadir, "Path to chain db", true)->check(CLI::ExistingDirectory);

    app.add_option("--from", options.block_from, "Initial block number to process (inclusive)", true)
        ->check(CLI::Range(1u, UINT32_MAX));
    app.add_option("--to", options.block_to, "Final block number to process (inclusive)", true)
        ->check(CLI::Range(1u, UINT32_MAX));

    app.add_flag("--debug", options.debug, "May print some debug/trace info.");

    CLI11_PARSE(app, argc, argv);

    if (options.debug) {
        SILKWORM_LOG_VERBOSITY(LogLevel::Debug);
    }

    if (!options.block_from) options.block_from = 1u;  // Block 0 (genesis) has no transactions

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // If database path is provided (and has passed CLI::ExistingDirectory validator
    // check whether it is empty
    fs::path db_path(options.datadir);
    if (!fs::exists(db_path) || !fs::is_directory(db_path) || fs::is_empty(db_path)) {
        std::cerr << "Invalid or empty --chaindata \"" << options.datadir << "\"" << std::endl
                  << "Try --help for help" << std::endl;
        return -1;
    } else {
        fs::path db_file = fs::path(db_path / fs::path("mdbx.dat"));
        if (!fs::exists(db_file) || !fs::file_size(db_file)) {
            std::cerr << "Invalid or empty data file \"" << db_file.string() << "\"" << std::endl
                      << "Try --help for help" << std::endl;
            return -1;
        }
    }

    // Invoke proper action
    int rc{0};
    try {
        // Set database parameters
        db::EnvConfig db_config{options.datadir};
        db_config.set_readonly(false);
        auto env{db::open_env(db_config)};
        auto txn{env.start_read()};

        auto config{db::read_chain_config(txn)};
        if (!config.has_value()) {
            throw std::runtime_error("Invalid chain config");
        }
        if (config->seal_engine != SealEngineType::kEthash) {
            throw std::runtime_error("Not an Ethash PoW chain");
        }

        auto max_headers_height{db::stages::get_stage_progress(txn, db::stages::kSendersKey)};
        options.block_to = std::min(options.block_to, static_cast<uint32_t>(max_headers_height));

        // Initialize epoch
        auto epoch_num{options.block_from / ethash::epoch_length};
        SILKWORM_LOG(LogLevel::Info) << "Initializing Light Cache for DAG epoch " << epoch_num << std::endl;
        auto epoch_context{ethash::create_epoch_context(epoch_num)};

        auto canonical_hashes{db::open_cursor(txn, db::table::kCanonicalHashes)};

        // Loop blocks
        for (uint32_t block_num{options.block_from}; block_num <= options.block_to && !g_should_stop; block_num++) {
            if (epoch_context->epoch_number != (block_num / ethash::epoch_length)) {
                epoch_num = (block_num / ethash::epoch_length);
                SILKWORM_LOG(LogLevel::Info) << "Initializing Light Cache for DAG epoch " << epoch_num << std::endl;
                epoch_context = ethash::create_epoch_context(epoch_num);
            }

            auto block_key{db::block_key(block_num)};
            auto data{canonical_hashes.find(db::to_slice(block_key), /*throw_notfound*/ false)};
            if (!data) {
                throw std::runtime_error("Can't retrieve canonical hash for block " + std::to_string(block_num));
            }

            auto header_key{to_bytes32(db::from_iovec(data.value))};
            auto header{db::read_header(txn, block_num, header_key.bytes)};
            if (!header.has_value()) {
                throw std::runtime_error("Can't retrieve header for block " + std::to_string(block_num));
            }

            // Verify Proof of Work
            uint64_t nonce{ethash::be::uint64(*reinterpret_cast<uint64_t*>(header->nonce.data()))};

            auto boundary256{ethash::get_boundary_from_diff(header->difficulty)};
            auto seal_hash(header->hash(/*for_sealing =*/true));
            ethash::hash256 sealh256{*reinterpret_cast<ethash::hash256*>(seal_hash.bytes)};
            auto result{ethash::hash(*epoch_context, sealh256, nonce)};
            if (!ethash::is_less_or_equal(result.final_hash, boundary256)) {
                auto b{to_bytes32({boundary256.bytes, 32})};
                auto f{to_bytes32({result.final_hash.bytes, 32})};
                auto m{to_bytes32({result.mix_hash.bytes, 32})};

                std::cout << "\n Pow Verification error (above target) on block " << block_num << " : \n"
                          << "Boundary   " << to_hex(b) << "\n"
                          << "Final hash " << to_hex(f) << "\n"
                          << "Mix   hash " << to_hex(m) << std::endl;
                break;
            }

            // Check mix_hash match
            if (std::memcmp(result.mix_hash.bytes, header->mix_hash.bytes, 32) != 0) {
                auto m{to_bytes32({result.mix_hash.bytes, 32})};

                std::cout << "\n Pow Verification error (mismatch mix_hash) on block " << block_num << " : \n"
                          << "Computed mix_hash   " << to_hex(m) << "\n"
                          << "Header   mix_hash   " << to_hex(header->mix_hash) << std::endl;
                break;
            }

            if (!(block_num % 1000)) {
                SILKWORM_LOG(LogLevel::Info) << "At block height " << block_num << std::endl;
            }
        }

        SILKWORM_LOG(LogLevel::Info) << "Complete !" << std::endl;

    } catch (const fs::filesystem_error& ex) {
        SILKWORM_LOG(LogLevel::Error) << ex.what() << " Check your filesystem permissions" << std::endl;
    } catch (const std::exception& ex) {
        SILKWORM_LOG(LogLevel::Error) << ex.what() << std::endl;
    }

    return rc;
}
