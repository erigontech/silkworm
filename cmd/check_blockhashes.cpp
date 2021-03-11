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

#include <CLI/CLI.hpp>
#include <boost/endian/conversion.hpp>
#include <boost/filesystem.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/etl/collector.hpp>

using namespace silkworm;

int main(int argc, char* argv[]) {
    namespace fs = boost::filesystem;

    CLI::App app{"Check Blockhashes => BlockNumber mapping in database"};

    std::string db_path{db::default_path()};
    app.add_option("--chaindata", db_path, "Path to a database populated by Turbo-Geth", true)
        ->check(CLI::ExistingDirectory);
    CLI11_PARSE(app, argc, argv);

    // Check data.mdb exists in provided directory
    fs::path db_file{fs::path(db_path) / fs::path("data.mdb")};
    if (!fs::exists(db_file)) {
        SILKWORM_LOG(LogError) << "Can't find a valid TG data file in " << db_path << std::endl;
        return -1;
    }

    fs::path datadir(db_path);

    try {
        lmdb::DatabaseConfig db_config{db_path};
        std::shared_ptr<lmdb::Environment> env{lmdb::get_env(db_config)};
        std::unique_ptr<lmdb::Transaction> txn{env->begin_ro_transaction()};

        auto header_table{txn->open(db::table::kBlockHeaders)};
        auto blockhashes_table{txn->open(db::table::kHeaderNumbers)};
        uint32_t scanned_headers{0};

        MDB_val mdb_key, mdb_data;
        SILKWORM_LOG(LogInfo) << "Checking Block Hashes..." << std::endl;
        int rc{header_table->get_first(&mdb_key, &mdb_data)};

        // Check if each hash has the correct number according to the header table
        while (!rc) {
            ByteView key{db::from_mdb_val(mdb_key)};

            if (key.size() != 40) {
                rc = header_table->get_next(&mdb_key, &mdb_data);
                continue;
            }

            scanned_headers++;
            auto hash{key.substr(8, 40)};
            auto expected_number{key.substr(0, 8)};
            auto actual_number{blockhashes_table->get(hash)};

            if (!actual_number.has_value()) {
                uint64_t expected_block = boost::endian::load_big_u64(expected_number.data());
                SILKWORM_LOG(LogError) << "Hash " << to_hex(hash) << " (block " << expected_block << ") not found in "
                                       << db::table::kHeaderNumbers.name << " table " << std::endl;

            } else if (actual_number->compare(expected_number) != 0) {
                uint64_t expected_block = boost::endian::load_big_u64(expected_number.data());
                uint64_t actual_block = boost::endian::load_big_u64(actual_number->data());
                SILKWORM_LOG(LogError) << "Hash " << to_hex(hash) << " should match block " << expected_block
                                       << " but got " << actual_block << std::endl;
            }
            if (scanned_headers % 100000 == 0) {
                SILKWORM_LOG(LogInfo) << "Scanned headers " << scanned_headers << std::endl;
            }
            rc = header_table->get_next(&mdb_key, &mdb_data);
        }
        if (rc && rc != MDB_NOTFOUND) {
            // We might have stumbled into some IO error
            lmdb::err_handler(rc);
        }

        SILKWORM_LOG(LogInfo) << "Done!" << std::endl;
    } catch (const std::exception& ex) {
        SILKWORM_LOG(LogError) << ex.what() << std::endl;
        return -5;
    }
    return 0;
}
