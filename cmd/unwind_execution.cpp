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

#include <iostream>

#include <CLI/CLI.hpp>

#include <silkworm/common/directories.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/stagedsync/stagedsync.hpp>

using namespace silkworm;

int main(int argc, char* argv[]) {
    namespace fs = std::filesystem;

    CLI::App app{"Unwind Execution Stage"};

    std::string chaindata{DataDirectory{}.chaindata().path().string()};
    BlockNum unwind_to{0};
    app.add_option("--chaindata", chaindata, "Path to a database populated by Turbo-Geth", /*defaulted=*/true)
        ->check(CLI::ExistingDirectory);
    app.add_option("--unwind-to", unwind_to, "Specify unwinding point", /*defaulted=*/false)->required();
    CLI11_PARSE(app, argc, argv);

    try {
        auto data_dir{DataDirectory::from_chaindata(chaindata)};
        data_dir.deploy();
        db::EnvConfig db_config{data_dir.chaindata().path().string()};
        auto env{db::open_env(db_config)};
        db::TransactionManager tm{env};
        stagedsync::success_or_throw(stagedsync::unwind_execution(tm, data_dir.etl().path(), unwind_to));
    } catch (const std::exception& ex) {
        SILKWORM_LOG(LogLevel::Error) << ex.what() << std::endl;
        return -5;
    }
    SILKWORM_LOG(LogLevel::Info) << "All Done!" << std::endl;
    return 0;
}
