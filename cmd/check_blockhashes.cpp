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
        SILKWORM_LOG(LogLevels::LogError) << "Can't find a valid TG data file in " << db_path << std::endl;
        return -1;
    }

    fs::path datadir(db_path);

    try {
        lmdb::DatabaseConfig db_config{db_path};
        std::shared_ptr<lmdb::Environment> env{lmdb::get_env(db_config)};
        std::unique_ptr<lmdb::Transaction> txn{env->begin_ro_transaction()};

        auto canonical_hashes_table{txn->open(db::table::kCanonicalHashes)};
        auto blockhashes_table{txn->open(db::table::kHeaderNumbers)};
        uint32_t scanned_headers{0};

        MDB_val mdb_key, mdb_data;
        SILKWORM_LOG(LogLevels::LogInfo) << "Checking Block Hashes..." << std::endl;
        int rc{canonical_hashes_table->get_first(&mdb_key, &mdb_data)};

        // Check if each hash has the correct number according to the header table
        while (!rc) {
            ByteView hash_key_view{db::from_mdb_val(mdb_key)};    // Height number
            ByteView hash_data_view{db::from_mdb_val(mdb_data)};  // Canonical Hash
            auto block_data_view{blockhashes_table->get(hash_data_view)};

            if (!block_data_view.has_value()) {
                uint64_t hash_block_number = boost::endian::load_big_u64(hash_key_view.data());
                SILKWORM_LOG(LogLevels::LogError)
                    << "Hash " << to_hex(hash_data_view) << " (block " << hash_block_number << ") not found in "
                    << db::table::kHeaderNumbers.name << " table " << std::endl;

            } else if (block_data_view->compare(hash_key_view) != 0) {
                uint64_t hash_height = boost::endian::load_big_u64(hash_key_view.data());
                uint64_t block_height = boost::endian::load_big_u64(block_data_view->data());
                SILKWORM_LOG(LogLevels::LogError) << "Hash " << to_hex(hash_data_view) << " should match block "
                                                  << hash_height << " but got " << block_height << std::endl;
            }

            if (++scanned_headers % 100000 == 0) {
                SILKWORM_LOG(LogLevels::LogInfo) << "Scanned headers " << scanned_headers << std::endl;
            }
            rc = canonical_hashes_table->get_next(&mdb_key, &mdb_data);
        }
        if (rc && rc != MDB_NOTFOUND) {
            // We might have stumbled into some IO error
            lmdb::err_handler(rc);
        }

        SILKWORM_LOG(LogLevels::LogInfo) << "Done!" << std::endl;
    } catch (const std::exception& ex) {
        SILKWORM_LOG(LogLevels::LogError) << ex.what() << std::endl;
        return -5;
    }
    return 0;
}
