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
#include <boost/endian/conversion.hpp>
#include <boost/filesystem.hpp>

#include <fstream>
#include <json/json.h>

#include <silkworm/common/log.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/etl/collector.hpp>

using namespace silkworm;


int main() {
    namespace fs = boost::filesystem;

    CLI::App app{"Generates Tc Hashes => BlockNumber mapping in database"};

    std::string db_path{db::default_path()};
    // We Initialize the database and open it
    lmdb::DatabaseConfig db_config{db_path};
    db_config.set_readonly(false);
    std::shared_ptr<lmdb::Environment> env{lmdb::get_env(db_config)};
    std::unique_ptr<lmdb::Transaction> txn{env->begin_rw_transaction()};
    // We create all tables
    for(const auto& table: db::table::kTables) {
        auto target_table{txn->open(table)};
        size_t target_table_rcount{0};
        lmdb::err_handler(target_table->get_rcount(&target_table_rcount));
        if (target_table_rcount > 0) {
            std::cout << "you need to code: " << target_table_rcount<< " in: "<< table.name << std::endl;
        }
    }
}
