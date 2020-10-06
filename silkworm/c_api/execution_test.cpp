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

#include "execution.h"

#include <catch2/catch.hpp>
#include <silkworm/chain/config.hpp>
#include <silkworm/common/temp_dir.hpp>
#include <silkworm/db/chaindb.hpp>
#include <silkworm/db/tables.hpp>

TEST_CASE("Execution API") {
    using namespace silkworm;

    TemporaryDirectory tmp_dir{};
    lmdb::options db_opts{};
    db_opts.map_size = 32 << 20;  //  32MiB
    std::shared_ptr<lmdb::Environment> db_env{lmdb::get_env(tmp_dir.path(), db_opts)};
    std::unique_ptr<lmdb::Transaction> txn{db_env->begin_rw_transaction()};

    uint64_t from{1};
    uint64_t to{1};

    uint64_t chain_id{404};
    CHECK(silkworm_execute(*txn->handle(), chain_id, from, to, nullptr) == kSilkwormUnknownChainId);

    chain_id = kMainnetConfig.chain_id;
    int lmdb_error_code{MDB_SUCCESS};
    CHECK(silkworm_execute(*txn->handle(), chain_id, from, to, &lmdb_error_code) == kSilkwormLmdbError);
    CHECK(lmdb_error_code == MDB_NOTFOUND);

    db::table::create_all(*txn);
}
