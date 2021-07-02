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
#include <iomanip>
#include <string>
#include <thread>
#include <unordered_map>

#include <CLI/CLI.hpp>
#include <boost/endian/conversion.hpp>
#include <cbor/decoder.h>

#include <silkworm/common/cast.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/bitmap.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/etl/collector.hpp>
#include <silkworm/stagedsync/stagedsync.hpp>

using namespace silkworm;

int main(int argc, char *argv[]) {
    namespace fs = std::filesystem;

    CLI::App app{"Generates Log Index"};

    std::string db_path{db::default_path()};
    bool full{false};
    app.add_option("--chaindata", db_path, "Path to a database populated by Erigon", true)
        ->check(CLI::ExistingDirectory);

    app.add_flag("--full", full, "Start making history indexes from block 0");

    CLI11_PARSE(app, argc, argv);

    // Check data file exists in provided directory
    fs::path db_file{fs::path(db_path) / fs::path(MDBX_DATANAME)};
    if (!fs::exists(db_file)) {
        SILKWORM_LOG(LogLevel::Error) << "Can't find a valid Erigon data file in " << db_path << std::endl;
        return -1;
    }
    fs::path datadir(db_path);
    fs::path etl_path(datadir.parent_path() / fs::path("etl-temp"));
    fs::create_directories(etl_path);
    etl::Collector topic_collector(etl_path.string().c_str(), /* flush size */ 256 * kMebi);
    etl::Collector addresses_collector(etl_path.string().c_str(), /* flush size */ 256 * kMebi);

    db::EnvConfig db_config{db_path};
    db_config.set_readonly(false);

    try {

        if (full) {
            auto env{db::open_env(db_config)};
            auto txn{env.start_write()};
            db::stages::set_stage_progress(txn, db::stages::kLogIndexKey, 0);
            auto map{db::open_map(txn, db::table::kLogTopicIndex)};
            txn.clear_map(map);
            map = db::open_map(txn, db::table::kLogAddressIndex);
            txn.clear_map(map);
            txn.commit();
            env.close();
        }

        stagedsync::check_stagedsync_error(stagedsync::stage_log_index(db_config));
    } catch (const std::exception &ex) {
        SILKWORM_LOG(LogLevel::Error) << ex.what() << std::endl;
        return -5;
    }
    return 0;
}
