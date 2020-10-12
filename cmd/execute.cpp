/*
   Copyright 2020 The Silkworm Authors

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

#include <silkworm/c_api/execution.h>

#include <CLI/CLI.hpp>
#include <iostream>
#include <silkworm/chain/config.hpp>
#include <silkworm/db/chaindb.hpp>
#include <silkworm/db/util.hpp>

int main(int argc, char* argv[]) {
    using namespace silkworm;

    CLI::App app{"Execute Ethereum blocks and write the result into the DB"};
    std::string db_path{db::default_path()};
    app.add_option("-d,--datadir", db_path, "Path to a database populated by Turbo-Geth");
    CLI11_PARSE(app, argc, argv);

    std::shared_ptr<lmdb::Environment> env{lmdb::get_env(db_path.c_str())};
    std::unique_ptr<lmdb::Transaction> txn{env->begin_rw_transaction()};

    uint64_t block_number{1};
    int lmdb_error_code{MDB_SUCCESS};
    SilkwormStatusCode status{
        silkworm_execute_block(*txn->handle(), kMainnetConfig.chain_id, block_number, &lmdb_error_code)};

    lmdb::err_handler(txn->commit());

    if (status == kSilkwormSuccess) {
        std::cout << "Success 🥳\n";
    } else if (status == kSilkwormLmdbError) {
        std::cout << "LMDB error " << lmdb_error_code << "\n";
    } else {
        std::cout << "Failure " << status << "\n";
    }

    return status;
}
