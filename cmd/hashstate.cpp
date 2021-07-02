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

#include <silkworm/stagedsync/stagedsync.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/db/stages.hpp>

using namespace silkworm;
namespace fs = std::filesystem;


int main(int argc, char* argv[]) {
    CLI::App app{"Generates Hashed state"};

    std::string db_path{db::default_path()};
    bool full{false};
    bool incrementally{false};
    bool reset{false};
    app.add_option("--chaindata", db_path, "Path to a database populated by Erigon", true)
        ->check(CLI::ExistingDirectory);

    app.add_flag("--full", full, "Start making lookups from block 0");
    app.add_flag("--increment", incrementally, "Use incremental method");
    app.add_flag("--reset", reset, "Reset HashState");
    CLI11_PARSE(app, argc, argv);

    // Check data.mdb exists in provided directory
    fs::path db_file{fs::path(db_path) / fs::path("mdbx.dat")};
    if (!fs::exists(db_file)) {
        SILKWORM_LOG(LogLevel::Error) << "Can't find a valid Erigon data file in " << db_path << std::endl;
        return -1;
    }
    fs::path datadir(db_path);
    fs::path etl_path(datadir.parent_path() / fs::path("etl-temp"));

    db::EnvConfig db_config{db_path};
    db_config.set_readonly(false);
    auto env{db::open_env(db_config)};
    auto txn{env.start_write()};

    try {
        if (full || reset) {
            txn.clear_map(db::open_map(txn, db::table::kHashedAccounts));
            txn.clear_map(db::open_map(txn, db::table::kHashedStorage));
            txn.clear_map(db::open_map(txn, db::table::kContractCode));
            db::stages::set_stage_progress(txn, db::stages::kHashStateKey, 0);
            if (reset) {
                SILKWORM_LOG(LogLevel::Info) << "Reset Complete!" << std::endl;
                txn.commit();
                return 0;
            }
        }
        SILKWORM_LOG(LogLevel::Info) << "Starting HashState" << std::endl;

        auto last_processed_block_number{db::stages::get_stage_progress(txn, db::stages::kHashStateKey)};
        if (last_processed_block_number != 0 || incrementally) {
            SILKWORM_LOG(LogLevel::Info) << "Starting Account Hashing" << std::endl;
            stagedsync::hashstate_promote(txn, stagedsync::HashstateOperation::HashAccount);
            SILKWORM_LOG(LogLevel::Info) << "Starting Storage Hashing" << std::endl;
            stagedsync::hashstate_promote(txn, stagedsync::HashstateOperation::HashStorage);
            SILKWORM_LOG(LogLevel::Info) << "Hashing Code Keys" << std::endl;
            stagedsync::hashstate_promote(txn, stagedsync::HashstateOperation::Code);
        } else {
            stagedsync::hashstate_promote_clean_state(txn, etl_path.string());
            stagedsync::hashstate_promote_clean_code(txn, etl_path.string());
        }
        // Update progress height with last processed block
        db::stages::set_stage_progress(txn, db::stages::kHashStateKey,
                                       db::stages::get_stage_progress(txn, db::stages::kExecutionKey));
        txn.commit();
        SILKWORM_LOG(LogLevel::Info) << "All Done!" << std::endl;
    } catch (const std::exception& ex) {
        SILKWORM_LOG(LogLevel::Error) << ex.what() << std::endl;
        return -5;
    }
}
