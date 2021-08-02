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

#include <CLI/CLI.hpp>

#include <silkworm/common/data_dir.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/etl/collector.hpp>
#include <silkworm/stagedsync/stagedsync.hpp>

using namespace silkworm;

int main(int argc, char* argv[]) {
    namespace fs = std::filesystem;

    CLI::App app{"Unwind Transaction Unwind Stage"};

    std::string chaindata{DataDirectory{}.get_chaindata_path().string()};
    uint32_t unwind_to{UINT32_MAX};
    app.add_option("--chaindata", chaindata, "Path to a database populated by Turbo-Geth", true)
        ->check(CLI::ExistingDirectory);
    app.add_option("--unwind-to", unwind_to, "Specify unwinding point", false)
        ->required()
        ->check(CLI::Range(0u, UINT32_MAX));

    CLI11_PARSE(app, argc, argv);

    try {
        auto data_dir{DataDirectory::from_chaindata(chaindata)};
        data_dir.create_tree();
        db::EnvConfig db_config{data_dir.get_chaindata_path().string()};
        auto env{db::open_env(db_config)};
        stagedsync::TransactionManager tm{env};
        stagedsync::check_stagedsync_error(stagedsync::unwind_tx_lookup(tm, data_dir.get_etl_path(), unwind_to));

    } catch (const std::exception& ex) {
        SILKWORM_LOG(LogLevel::Error) << ex.what() << std::endl;
        return -5;
    }
    return 0;
}
