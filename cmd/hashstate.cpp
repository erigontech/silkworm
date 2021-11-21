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

#include <silkworm/common/directories.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/stagedsync/stagedsync.hpp>

using namespace silkworm;
namespace fs = std::filesystem;

int main(int argc, char* argv[]) {
    CLI::App app{"Generates Hashed state"};

    std::string chaindata{DataDirectory{}.chaindata().path().string()};
    bool full{false};
    bool incrementally{false};
    bool reset{false};
    app.add_option("--chaindata", chaindata, "Path to a database populated by Erigon", true)
        ->check(CLI::ExistingDirectory);

    app.add_flag("--full", full, "Start making lookups from block 0");
    app.add_flag("--increment", incrementally, "Use incremental method");
    app.add_flag("--reset", reset, "Reset HashState");
    CLI11_PARSE(app, argc, argv);

    auto data_dir{DataDirectory::from_chaindata(chaindata)};
    data_dir.deploy();
    db::EnvConfig db_config{data_dir.chaindata().path().string()};
    auto env{db::open_env(db_config)};
    auto txn{env.start_write()};

    try {
        if (full || reset) {
            txn.clear_map(db::open_map(txn, db::table::kHashedAccounts));
            txn.clear_map(db::open_map(txn, db::table::kHashedStorage));
            txn.clear_map(db::open_map(txn, db::table::kContractCode));
            db::stages::write_stage_progress(txn, db::stages::kHashStateKey, 0);
            if (reset) {
                log::Info() << "Reset Complete!";
                txn.commit();
                return 0;
            }
        }
        log::Info() << "Starting HashState";

        auto last_processed_block_number{db::stages::read_stage_progress(txn, db::stages::kHashStateKey)};
        if (last_processed_block_number != 0 || incrementally) {
            log::Info() << "Starting Account Hashing";
            stagedsync::hashstate_promote(txn, stagedsync::HashstateOperation::HashAccount);
            log::Info() << "Starting Storage Hashing";
            stagedsync::hashstate_promote(txn, stagedsync::HashstateOperation::HashStorage);
            log::Info() << "Hashing Code Keys";
            stagedsync::hashstate_promote(txn, stagedsync::HashstateOperation::Code);
        } else {
            stagedsync::hashstate_promote_clean_state(txn, data_dir.etl().path().string());
            stagedsync::hashstate_promote_clean_code(txn, data_dir.etl().path().string());
        }
        // Update progress height with last processed block
        db::stages::write_stage_progress(txn, db::stages::kHashStateKey,
                                         db::stages::read_stage_progress(txn, db::stages::kExecutionKey));
        txn.commit();
        log::Info() << "All Done!";
    } catch (const std::exception& ex) {
        log::Error() << ex.what();
        return -5;
    }
}
