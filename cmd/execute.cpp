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

#include <CLI/CLI.hpp>
#include <magic_enum.hpp>

#include <silkworm/common/directories.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/stagedsync/stagedsync.hpp>

int main(int argc, char* argv[]) {
    using namespace silkworm;

    CLI::App app{"Execute Ethereum blocks and write the result into the DB"};

    std::string chaindata{DataDirectory{}.chaindata().path().string()};

    bool prune{false};
    uint64_t blocks_to_keep{96000};

    app.add_option("--chaindata", chaindata, "Path to a database populated by Erigon", true)
        ->check(CLI::ExistingDirectory);

    std::string batch_size_str{"512MB"};
    app.add_option("--batch", batch_size_str, "Batch size of DB changes to accumulate before committing", true);

    app.add_flag("--prune", prune, "Enable pruned mode");

    app.add_option("--blocks-to-keep", blocks_to_keep, "How many block to keep in pruned mode");

    CLI11_PARSE(app, argc, argv);

    auto batch_size{parse_size(batch_size_str)};
    if (!batch_size.has_value()) {
        log::Error() << "Invalid --batch value provided : " << batch_size_str;
        return -3;
    }

    log::Info() << "Starting block execution. DB: " << chaindata;

    log::set_verbosity(log::Level::kDebug);

    uint64_t prune_from{0};
    auto data_dir{DataDirectory::from_chaindata(chaindata)};
    data_dir.deploy();
    db::EnvConfig db_config{data_dir.chaindata().path().string()};
    db_config.create = false;
    auto env{db::open_env(db_config)};
    stagedsync::TransactionManager tm{env};

    if (prune) {
        prune_from = db::stages::read_stage_progress(*tm, db::stages::kSendersKey) - blocks_to_keep;
    }
    auto res{stagedsync::stage_execution(tm, data_dir.etl().path(), batch_size.value(), prune_from)};

    if (res != stagedsync::StageResult::kSuccess) {
        log::Info() << "Execution returned : " << magic_enum::enum_name<stagedsync::StageResult>(res);
    }
    return magic_enum::enum_integer<stagedsync::StageResult>(res);
}
