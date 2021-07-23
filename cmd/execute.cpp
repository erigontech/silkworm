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
#include <magic_enum.hpp>

#include <silkworm/common/data_dir.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/stagedsync/stagedsync.hpp>

int main(int argc, char* argv[]) {
    using namespace silkworm;

    CLI::App app{"Execute Ethereum blocks and write the result into the DB"};

    std::string chaindata{DataDirectory{}.get_chaindata_path().string()};
    app.add_option("--chaindata", chaindata, "Path to a database populated by Erigon", true)
        ->check(CLI::ExistingDirectory);

    CLI11_PARSE(app, argc, argv);

    SILKWORM_LOG(LogLevel::Info) << "Starting block execution. DB: " << chaindata << std::endl;

    db::EnvConfig db_config{chaindata};
    db_config.create = false;
    auto res{stagedsync::stage_execution(db_config)};
    if (res != stagedsync::StageResult::kSuccess) {
        SILKWORM_LOG(LogLevel::Info) << "Execution returned : " << magic_enum::enum_name<stagedsync::StageResult>(res)
                                     << std::endl;
    }
    return magic_enum::enum_integer<stagedsync::StageResult>(res);
}
