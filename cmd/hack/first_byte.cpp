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

#include <array>

#include <CLI/CLI.hpp>

#include <silkworm/common/data_dir.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/db/mdbx.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/tables.hpp>

int main(int argc, char* argv[]) {
    using namespace silkworm;

    CLI::App app{"Produce a histogram of the first byte of deployed smart contracts"};

    std::string chaindata{DataDirectory{}.get_chaindata_path().string()};
    app.add_option("--chaindata", chaindata, "Path to a database populated by Erigon", true)
        ->check(CLI::ExistingDirectory);

    CLI11_PARSE(app, argc, argv);

    SILKWORM_LOG(LogLevel::Info) << "Starting. DB: " << chaindata << "\n";

    try {
        db::EnvConfig db_config{chaindata};
        auto env{db::open_env(db_config)};
        auto txn{env.start_read()};

        std::array<size_t, 256> histogram{};

        auto code_table{db::open_cursor(txn, db::table::kCode)};
        db::for_each(code_table, [&histogram](mdbx::cursor::move_result& entry) {
            if (entry.value.length() > 0) {
                uint8_t first_byte{entry.value.at(0)};
                ++histogram[first_byte];
            }
            return true;
        });

        BlockNum last_block{db::stages::get_stage_progress(txn, db::stages::kExecutionKey)};
        SILKWORM_LOG(LogLevel::Info) << "Done. Last block: " << last_block << "\n\n";

        for (size_t i{0}; i < 256; ++i) {
            std::cout << std::hex << i << '\t' << std::dec << histogram[i] << "\n";
        }

    } catch (const std::exception& ex) {
        SILKWORM_LOG(LogLevel::Error) << ex.what() << "\n";
        return -1;
    }
    return 0;
}
