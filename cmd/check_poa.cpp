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
#include <ethash/ethash.hpp>
#include <ethash/keccak.hpp>

#include <silkworm/chain/config.hpp>
#include <silkworm/common/directories.hpp>
#include <silkworm/common/endian.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/consensus/clique/clique.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/types/block.hpp>
#include <silkworm/stagedsync/transaction_manager.hpp>
#include <silkworm/db/buffer.hpp>
#include <magic_enum.hpp>

namespace fs = std::filesystem;
using namespace silkworm;

std::atomic_bool g_should_stop{false};  // Request for stop from user or OS

struct app_options_t {
    std::string datadir{};          // Provided database path
};

int main(int argc, char* argv[]) {
    // Init command line parser
    CLI::App app("Check PoW.");
    app_options_t options{};
    options.datadir = DataDirectory{}.chaindata().path().string();  // Default chain data db path

    // Command line arguments
    app.add_option("--chaindata", options.datadir, "Path to chain db", true)->check(CLI::ExistingDirectory);

    CLI11_PARSE(app, argc, argv);

    // Invoke proper action
    int rc{0};

    auto data_dir{DataDirectory::from_chaindata(options.datadir)};
    data_dir.deploy();
    options.datadir = data_dir.chaindata().path().string();

    // Set database parameters
    db::EnvConfig db_config{options.datadir};
    auto env{db::open_env(db_config)};
    stagedsync::TransactionManager txn{env};

    auto config{db::read_chain_config(*txn)};
    if (!config.has_value()) {
        throw std::runtime_error("Invalid chain config");
    }
    if (config->seal_engine != SealEngineType::kClique) {
        throw std::runtime_error("Not a PoA chain");
    }

    auto headers{db::open_cursor(*txn, db::table::kHeaders)};
    auto header_data{headers.to_first()};
    consensus::Clique engine(kDefaultCliqueConfig);
    try {
        // Loop blocks
        while(header_data) {
            auto key{db::from_slice(header_data.key)};
            auto encoded_header{db::from_slice(header_data.value)};
            if (header_data.key.size() != 40) {
                header_data = headers.to_next(false);
                continue;
            }
            BlockHeader header{};
            uint64_t block_num{endian::load_big_u64(&key[0])};
            db::Buffer buffer{*txn, block_num};
            if (rlp::decode(encoded_header, header) != rlp::DecodingResult::kOk) {
                std::cout << "decoding" << std::endl;
                return -2;
            }
            if (block_num % 1 == 0) {
                std::cout << "Now at Block: " << block_num << std::endl;
            }
            auto err{engine.validate_block_header(header, buffer, *config)};
            if (err != ValidationResult::kOk) {
                std::cout << "fail, at " << block_num << ", due to: " << std::string(magic_enum::enum_name<ValidationResult>(err)) << std::endl;
                return -1;
            }
            buffer.write_to_db();
            header_data = headers.to_next(false);
        }
    } catch (const fs::filesystem_error& ex) {
        SILKWORM_LOG(LogLevel::Error) << ex.what() << " Check your filesystem permissions" << std::endl;
    } catch (const std::exception& ex) {
        SILKWORM_LOG(LogLevel::Error) << ex.what() << std::endl;
    }

    return rc;
}
