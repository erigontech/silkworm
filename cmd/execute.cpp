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
#include <boost/endian/conversion.hpp>

#include <silkworm/common/log.hpp>
#include <silkworm/common/magic_enum.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/execution/execution.hpp>
#include <silkworm_tg_api.h>

int main(int argc, char* argv[]) {
    using namespace silkworm;

    CLI::App app{"Execute Ethereum blocks and write the result into the DB"};

    std::string chaindata{db::default_path()};
    app.add_option("--chaindata", chaindata, "Path to a database populated by Erigon", true)
        ->check(CLI::ExistingDirectory);

    uint64_t to_block{UINT64_MAX};
    app.add_option("--to", to_block, "Block execute up to");

    std::string batch_size_str{"512MB"};
    app.add_option("--batch", batch_size_str, "Batch size of DB changes to accumulate before committing", true);

    CLI11_PARSE(app, argc, argv);

    namespace fs = std::filesystem;

    // Check data file exists in provided directory
    std::filesystem::path db_path{chaindata};
    auto db_file{db::get_datafile_path(db_path)};
    if (!fs::exists(db_file) || !fs::file_size(db_file)) {
        std::cerr << "Invalid or empty data file \"" << db_file.string() << "\"" << std::endl
                  << "Try --help for help" << std::endl;
        return -1;
    }

    auto batch_size{parse_size(batch_size_str)};
    if (!batch_size.has_value()) {
        SILKWORM_LOG(LogLevel::Error) << "Invalid --batch value provided : " << batch_size_str << std::endl;
        return -3;
    }

    SILKWORM_LOG(LogLevel::Info) << "Starting block execution. DB: " << db_file << std::endl;

    try {

        db::EnvConfig db_config{db_path.string()};
        db_config.set_readonly(false);
        auto env{db::open_env(db_config)};
        auto txn{env.start_write()};

        bool write_receipts{db::read_storage_mode_receipts(txn)};
        auto chain_config{db::read_chain_config(txn)};
        if (!chain_config.has_value()) {
            throw std::runtime_error("Unable to retrieve chain config");
        }

        uint64_t previous_progress{db::stages::get_stage_progress(txn, db::stages::kExecutionKey)};
        uint64_t current_progress{previous_progress};

        for (uint64_t block_number{previous_progress + 1}; block_number <= to_block; ++block_number) {
            int db_error_code{0};
            SilkwormStatusCode status{silkworm_execute_blocks(txn, chain_config->chain_id, block_number,
                                                              to_block, *batch_size, write_receipts, &current_progress,
                                                              &db_error_code)};
            if (status != SilkwormStatusCode::kSilkwormSuccess &&
                status != SilkwormStatusCode::kSilkwormBlockNotFound) {
                SILKWORM_LOG(LogLevel::Error) << "Error in silkworm_execute_blocks: " << magic_enum::enum_name(status)
                                              << ", DB: " << db_error_code << std::endl;
                return magic_enum::enum_integer(status);
            }

            block_number = current_progress;

            db::stages::set_stage_progress(txn, db::stages::kExecutionKey, current_progress);
            txn.commit();

            if (status == SilkwormStatusCode::kSilkwormBlockNotFound) {
                break;
            }

            SILKWORM_LOG(LogLevel::Info) << "Blocks <= " << current_progress << " committed" << std::endl;
            txn = env.start_write();
        }

        if (current_progress > previous_progress) {
            SILKWORM_LOG(LogLevel::Info) << "All blocks <= " << current_progress << " executed and committed"
                                         << std::endl;
        } else {
            SILKWORM_LOG(LogLevel::Warn) << "Nothing to execute" << std::endl;
        }

    } catch (const std::exception& ex) {
        SILKWORM_LOG(LogLevel::Error) << ex.what() << std::endl;
        return -5;
    }

    return 0;
}
