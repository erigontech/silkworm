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

/*
Roughly corresponds to
https://github.com/ledgerwatch/erigon/tree/master/eth/stagedsync#stage-7-compute-state-root-stage

At the moment only full regeneration is supported, not incremental update.

The previous Generate Hashed State Stage must be performed prior to calling this executable.
*/

#include <filesystem>

#include <CLI/CLI.hpp>

#include <silkworm/common/log.hpp>
#include <silkworm/common/temp_dir.hpp>
#include <silkworm/db/mdbx.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/trie/db_trie.hpp>

int main(int argc, char* argv[]) {
    CLI::App app{"Generate account & storage tries in the DB and compute the state root"};

    using namespace silkworm;

    std::string db_path{db::default_path()};
    app.add_option("--chaindata", db_path, "Path to a database populated by Erigon", true)
        ->check(CLI::ExistingDirectory);

    CLI11_PARSE(app, argc, argv);

    namespace fs = std::filesystem;

    // Check data file exists in provided directory
    fs::path db_file{fs::path(db_path) / fs::path(MDBX_DATANAME)};
    if (!fs::exists(db_file)) {
        SILKWORM_LOG(LogLevel::Error) << "Can't find a valid Erigon data file in " << db_path << std::endl;
        return -1;
    }

    SILKWORM_LOG(LogLevel::Info) << "Regenerating account & storage tries. DB: " << db_file << std::endl;

    try {

        db::EnvConfig db_config{db_path};
        db_config.set_readonly(false);
        auto env{db::open_env(db_config)};
        auto txn{env.start_write()};

        TemporaryDirectory temp_dir;

        evmc::bytes32 state_root{trie::regenerate_db_tries(txn, temp_dir.path())};

        SILKWORM_LOG(LogLevel::Info) << "State root " << to_hex(state_root) << std::endl;
        txn.commit();

    } catch (const std::exception& ex) {
        SILKWORM_LOG(LogLevel::Error) << ex.what() << std::endl;
        return -5;
    }

    return 0;
}
