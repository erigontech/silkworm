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
#include <iostream>

#include <CLI/CLI.hpp>
#include <boost/endian/conversion.hpp>

#include <silkworm/common/data_dir.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/stagedsync/stagedsync.hpp>

using namespace silkworm;

int main(int argc, char* argv[]) {
    namespace fs = std::filesystem;

    CLI::App app{"Generates Tc Hashes => BlockNumber mapping in database"};

    std::string chaindata{DataDirectory{}.get_chaindata_path().string()};
    bool full{false};
    app.add_option("--chaindata", chaindata, "Path to a database populated by Erigon", true)
        ->check(CLI::ExistingDirectory);

    app.add_flag("--full", full, "Start making lookups from block 0");
    CLI11_PARSE(app, argc, argv);

    try {
        auto data_dir{DataDirectory::from_chaindata(chaindata)};
        data_dir.create_tree();
        db::EnvConfig db_config{data_dir.get_chaindata_path().string()};
        auto env{db::open_env(db_config)};

        if (full) {
            auto txn{env.start_write()};

            auto tx_map{db::open_map(txn, db::table::kTxLookup)};
            txn.clear_map(tx_map);
            db::stages::set_stage_progress(txn, db::stages::kTxLookupKey, 0);
            txn.commit();
        }

        stagedsync::TransactionManager tm{env};
        stagedsync::check_stagedsync_error(stagedsync::stage_tx_lookup(tm, data_dir.get_etl_path()));

    } catch (const std::exception& ex) {
        SILKWORM_LOG(LogLevel::Error) << ex.what() << std::endl;
        return -5;
    }
    return 0;
}
