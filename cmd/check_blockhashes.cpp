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

#include <CLI/CLI.hpp>
#include <boost/endian/conversion.hpp>

#include <silkworm/common/data_dir.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/common/stopwatch.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/etl/collector.hpp>

using namespace silkworm;

int main(int argc, char* argv[]) {
    namespace fs = std::filesystem;

    CLI::App app{"Check Blockhashes => BlockNumber mapping in database"};

    std::string chaindata{DataDirectory{}.get_chaindata_path().string()};
    app.add_option("--chaindata", chaindata, "Path to a database populated by Erigon", true)
        ->check(CLI::ExistingDirectory);
    CLI11_PARSE(app, argc, argv);

    try {
        auto data_dir{DataDirectory::from_chaindata(chaindata)};
        data_dir.create_tree();
        db::EnvConfig db_config{data_dir.get_chaindata_path().string()};
        auto env{db::open_env(db_config)};
        auto txn{env.start_read()};

        auto canonical_hashes_table{db::open_cursor(txn, db::table::kCanonicalHashes)};
        auto blockhashes_table{db::open_cursor(txn, db::table::kHeaderNumbers)};
        uint32_t scanned_headers{0};

        SILKWORM_LOG(LogLevel::Info) << "Checking Block Hashes..." << std::endl;
        auto canonica_hashes_data{canonical_hashes_table.to_first(/*throw_notfound*/ false)};

        StopWatch sw{};
        auto start_time{sw.start()};

        // Check if each hash has the correct number according to the header table
        while (canonica_hashes_data) {
            ByteView hash_data_view{db::from_slice(canonica_hashes_data.value)};  // Canonical Hash
            auto block_hashes_data{blockhashes_table.find(canonica_hashes_data.value, /*throw_notfound*/ false)};
            if (!block_hashes_data) {
                uint64_t hash_block_number{
                    boost::endian::load_big_u64(static_cast<uint8_t*>(canonica_hashes_data.key.iov_base))};
                SILKWORM_LOG(LogLevel::Error)
                    << "Hash " << to_hex(hash_data_view) << " (block " << hash_block_number << ") not found in "
                    << db::table::kHeaderNumbers.name << " table " << std::endl;

            } else if (block_hashes_data.value != canonica_hashes_data.key) {
                uint64_t hash_height =
                    boost::endian::load_big_u64(static_cast<uint8_t*>(canonica_hashes_data.key.iov_base));
                uint64_t block_height =
                    boost::endian::load_big_u64(static_cast<uint8_t*>(block_hashes_data.value.iov_base));
                SILKWORM_LOG(LogLevel::Error) << "Hash " << to_hex(hash_data_view) << " should match block "
                                              << hash_height << " but got " << block_height << std::endl;
            }

            if (++scanned_headers % 100000 == 0) {
                auto [_, duration] = sw.lap();
                SILKWORM_LOG(LogLevel::Info)
                    << "Scanned headers " << scanned_headers << " in " << sw.format(duration) << std::endl;
            }
            canonica_hashes_data = canonical_hashes_table.to_next(/*throw_notfound*/ false);
        }
        auto [end_time, _] = sw.lap();
        SILKWORM_LOG(LogLevel::Info) << "Done! " << sw.format(end_time - start_time) << std::endl;
    } catch (const std::exception& ex) {
        SILKWORM_LOG(LogLevel::Error) << ex.what() << std::endl;
        return -5;
    }
    return 0;
}
