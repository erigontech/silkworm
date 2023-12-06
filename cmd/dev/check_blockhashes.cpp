/*
   Copyright 2022 The Silkworm Authors

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

#include <CLI/CLI.hpp>

#include <silkworm/core/common/endian.hpp>
#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/common/stopwatch.hpp>
#include <silkworm/node/db/tables.hpp>

using namespace silkworm;

int main(int argc, char* argv[]) {
    CLI::App app{"Check Blockhashes => BlockNumber mapping in database"};

    std::string chaindata{DataDirectory{}.chaindata().path().string()};
    app.add_option("--chaindata", chaindata, "Path to a database populated by Erigon")
        ->capture_default_str()
        ->check(CLI::ExistingDirectory);
    CLI11_PARSE(app, argc, argv);

    try {
        auto data_dir{DataDirectory::from_chaindata(chaindata)};
        data_dir.deploy();
        db::EnvConfig db_config{data_dir.chaindata().path().string()};
        auto env{db::open_env(db_config)};
        auto txn{env.start_read()};

        auto canonical_hashes_table{db::open_cursor(txn, db::table::kCanonicalHashes)};
        auto blockhashes_table{db::open_cursor(txn, db::table::kHeaderNumbers)};
        uint32_t scanned_headers{0};

        log::Info() << "Checking Block Hashes...";
        auto canonical_hashes_data{canonical_hashes_table.to_first(/*throw_notfound*/ false)};

        StopWatch sw{};
        auto start_time{sw.start()};

        // Check if each hash has the correct number according to the header table
        while (canonical_hashes_data) {
            ByteView hash_data_view{db::from_slice(canonical_hashes_data.value)};  // Canonical Hash
            auto block_hashes_data{blockhashes_table.find(canonical_hashes_data.value, /*throw_notfound*/ false)};
            if (!block_hashes_data) {
                uint64_t hash_block_number{
                    endian::load_big_u64(static_cast<uint8_t*>(canonical_hashes_data.key.data()))};
                log::Error() << "Hash " << to_hex(hash_data_view) << " (block " << hash_block_number
                             << ") not found in " << db::table::kHeaderNumbers.name << " table ";

            } else if (block_hashes_data.value != canonical_hashes_data.key) {
                uint64_t hash_height = endian::load_big_u64(static_cast<uint8_t*>(canonical_hashes_data.key.data()));
                uint64_t block_height = endian::load_big_u64(static_cast<uint8_t*>(block_hashes_data.value.data()));
                log::Error() << "Hash " << to_hex(hash_data_view) << " should match block " << hash_height
                             << " but got " << block_height;
            }

            if (++scanned_headers % 100000 == 0) {
                auto [_, duration] = sw.lap();
                log::Info() << "Scanned headers " << scanned_headers << " in " << StopWatch::format(duration);
            }
            canonical_hashes_data = canonical_hashes_table.to_next(/*throw_notfound*/ false);
        }
        auto [end_time, _] = sw.lap();
        log::Info() << "Done! " << StopWatch::format(end_time - start_time);
    } catch (const std::exception& ex) {
        log::Error() << ex.what();
        return -5;
    }
    return 0;
}
