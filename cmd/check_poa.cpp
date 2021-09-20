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

#include <filesystem>

#include <CLI/CLI.hpp>
#include <magic_enum.hpp>

#include <silkworm/chain/config.hpp>
#include <silkworm/common/directories.hpp>
#include <silkworm/common/endian.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/consensus/clique/clique.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/buffer.hpp>
#include <silkworm/db/stages.hpp>

namespace fs = std::filesystem;
using namespace silkworm;

std::atomic_bool g_should_stop{false};  // Request for stop from user or OS

struct app_options_t {
    std::string datadir{};
    uint64_t from_block{0};
};

int main(int argc, char* argv[]) {
    // Init command line parser
    CLI::App app("Check PoA.");
    app_options_t options{};

    // Command line arguments
    app.add_option("--chaindata", options.datadir, "Path to chain db", false)
        ->required(true)
        ->check(CLI::ExistingDirectory);
    app.add_option("--from", options.from_block, "Initial block to begin check from", true);
    CLI11_PARSE(app, argc, argv);

    // Invoke proper action
    int rc{0};
    try {
        auto data_dir{DataDirectory::from_chaindata(options.datadir)};
        data_dir.deploy();
        options.datadir = data_dir.chaindata().path().string();

        // Set database parameters
        db::EnvConfig db_config{options.datadir};
        auto env{db::open_env(db_config)};
        auto txn{env.start_write()};

        auto config{db::read_chain_config(txn)};
        if (!config.has_value()) {
            throw std::runtime_error("Invalid chain config");
        }

        if (config->seal_engine != SealEngineType::kClique) {
            throw std::runtime_error("Not a PoA chain");
        }
        consensus::Clique engine(consensus::kDefaultCliqueConfig);

        auto canonical{db::open_cursor(txn, db::table::kCanonicalHashes)};
        BlockNum expected_block_num{options.from_block};
        BlockNum block_num{0};

        // Loop canonical blocks from initial requested
        auto start_key{db::block_key(options.from_block)};
        auto canonical_data{canonical.find(db::to_slice(start_key), /*throw_notfound=*/false)};
        while (canonical_data) {
            block_num = endian::load_big_u64(static_cast<uint8_t*>(canonical_data.key.iov_base));
            if (block_num != expected_block_num) {
                throw std::runtime_error("Bad header sequence : expected #" + std::to_string(expected_block_num) +
                                         " got #" + std::to_string(block_num));
            }

            // Retrieve header
            auto header_hash{to_bytes32(db::from_slice(canonical_data.value))};
            auto header{db::read_header(txn, block_num, header_hash.bytes)};
            if (!header.has_value()) {
                throw std::runtime_error("Cannot retrieve header for block #" + std::to_string(block_num));
            }

            if (block_num % 10000 == 0) {
                std::cout << "Now at Block: " << block_num << std::endl;
            }

            db::Buffer buffer{txn, block_num};
            auto err{engine.validate_block_header(header.value(), buffer, *config)};
            if (err != ValidationResult::kOk) {
                throw std::runtime_error("Validation error at block #" + std::to_string(block_num) + " : " +
                                         std::string(magic_enum::enum_name<ValidationResult>(err)));
            }
            buffer.write_to_db();

            canonical_data = canonical.to_next(/*throw_notfound=*/false);
            expected_block_num++;
        }
        txn.commit();

    } catch (const fs::filesystem_error& ex) {
        SILKWORM_LOG(LogLevel::Error) << ex.what() << " Check your filesystem permissions" << std::endl;
        rc = -1;
    } catch (const std::exception& ex) {
        SILKWORM_LOG(LogLevel::Error) << ex.what() << std::endl;
        rc = -1;
    }

    return rc;
}
