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
#include <iomanip>
#include <iostream>
#include <string>
#include <unordered_map>

#include <CLI/CLI.hpp>
#include <boost/endian/conversion.hpp>

#include <silkworm/common/cast.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/bitmap.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/etl/collector.hpp>

using namespace silkworm;

constexpr size_t kBitmapBufferSizeLimit = 256 * kMebi;

int main(int argc, char *argv[]) {
    namespace fs = std::filesystem;

    CLI::App app{"Generates History Indexes"};

    std::string db_path{db::default_path()};
    bool full{false}, storage{false};
    app.add_option("--chaindata", db_path, "Path to a database populated by Erigon", true)
        ->check(CLI::ExistingDirectory);

    app.add_flag("--full", full, "Start making history indexes from block 0");
    app.add_flag("--storage", storage, "Do history of storages");

    CLI11_PARSE(app, argc, argv);

    // Check data.mdb exists in provided directory
    fs::path db_file{fs::path(db_path) / fs::path("data.mdb")};
    if (!fs::exists(db_file)) {
        SILKWORM_LOG(LogLevel::Error) << "Can't find a valid Erigon data file in " << db_path << std::endl;
        return -1;
    }
    fs::path datadir(db_path);
    fs::path etl_path(datadir.parent_path() / fs::path("etl-temp"));
    fs::create_directories(etl_path);
    etl::Collector collector(etl_path.string().c_str(), /* flush size */ 512 * kMebi);

    lmdb::DatabaseConfig db_config{db_path};
    db_config.set_readonly(false);
    std::shared_ptr<lmdb::Environment> env{lmdb::get_env(db_config)};
    std::unique_ptr<lmdb::Transaction> txn{env->begin_rw_transaction()};
    // We take data from header table and transform it and put it in blockhashes table
    lmdb::TableConfig changeset_config =
        storage ? db::table::kPlainStorageChangeSet : db::table::kPlainAccountChangeSet;
    lmdb::TableConfig index_config = storage ? db::table::kStorageHistory : db::table::kAccountHistory;
    const char *stage_key = storage ? db::stages::kStorageHistoryIndexKey : db::stages::kAccountHistoryKey;
    auto changeset_table{txn->open(changeset_config)};
    std::unordered_map<std::string, roaring::Roaring64Map> bitmaps;

    try {
        auto last_processed_block_number{db::stages::get_stage_progress(*txn, stage_key)};

        if (full) {
            last_processed_block_number = 0;
            txn->open(index_config, MDB_CREATE)->clear();
        }

        // Extract
        Bytes start(8, '\0');
        boost::endian::store_big_u64(&start[0], last_processed_block_number);
        MDB_val mdb_key{db::to_mdb_val(start)};
        MDB_val mdb_data;

        SILKWORM_LOG(LogLevel::Info) << "Started " << (storage ? "Storage" : "Account") << " Index Extraction"
                                     << std::endl;

        size_t allocated_space{0};
        uint64_t block_number{0};
        int rc{changeset_table->seek(&mdb_key, &mdb_data)};  // Sets cursor to nearest key greater equal than this
        while (!rc) {                                        /* Loop as long as we have no errors*/
            std::string composite_key;
            if (storage) {
                char composite_key_array[kHashLength + kAddressLength];
                std::memcpy(&composite_key_array[0], &static_cast<uint8_t *>(mdb_key.mv_data)[8], kAddressLength);
                std::memcpy(&composite_key_array[kAddressLength], mdb_data.mv_data, kHashLength);
                composite_key = std::string(composite_key_array);
            } else {
                composite_key = std::string(static_cast<char *>(mdb_data.mv_data), kAddressLength);
            }

            if (bitmaps.find(composite_key) == bitmaps.end()) {
                bitmaps.emplace(composite_key, roaring::Roaring64Map());
            }
            block_number = boost::endian::load_big_u64(static_cast<uint8_t *>(mdb_key.mv_data));
            bitmaps.at(composite_key).add(block_number);
            allocated_space += 8;
            if (64 * bitmaps.size() + allocated_space > kBitmapBufferSizeLimit) {
                for (const auto &[key, bm] : bitmaps) {
                    Bytes bitmap_bytes(bm.getSizeInBytes(), '\0');
                    bm.write(byte_ptr_cast(bitmap_bytes.data()));
                    etl::Entry entry{Bytes(byte_ptr_cast(key.c_str()), key.size()), bitmap_bytes};
                    collector.collect(entry);
                }
                SILKWORM_LOG(LogLevel::Info) << "Current Block: " << block_number << std::endl;
                bitmaps.clear();
                allocated_space = 0;
            }
            rc = changeset_table->get_next(&mdb_key, &mdb_data);
        }

        if (rc && rc != MDB_NOTFOUND) { /* MDB_NOTFOUND is not actually an error rather eof */
            lmdb::err_handler(rc);
        }

        for (const auto &[key, bm] : bitmaps) {
            Bytes bitmap_bytes(bm.getSizeInBytes(), '\0');
            bm.write(byte_ptr_cast(bitmap_bytes.data()));
            etl::Entry entry{Bytes(byte_ptr_cast(key.c_str()), key.size()), bitmap_bytes};
            collector.collect(entry);
        }
        bitmaps.clear();

        SILKWORM_LOG(LogLevel::Info) << "Latest Block: " << block_number << std::endl;
        // Proceed only if we've done something
        if (collector.size()) {
            SILKWORM_LOG(LogLevel::Info) << "Started Loading" << std::endl;

            unsigned int db_flags{last_processed_block_number ? 0u : MDB_APPEND};

            // Eventually load collected items WITH transform (may throw)
            collector.load(
                txn->open(index_config, MDB_CREATE).get(),
                [](etl::Entry entry, lmdb::Table *history_index_table, unsigned int db_flags) {
                    auto bm{roaring::Roaring64Map::readSafe(byte_ptr_cast(entry.value.data()), entry.value.size())};
                    Bytes last_chunk_index(entry.key.size() + 8, '\0');
                    std::memcpy(&last_chunk_index[0], &entry.key[0], entry.key.size());
                    boost::endian::store_big_u64(&last_chunk_index[entry.key.size()], UINT64_MAX);
                    auto previous_bitmap_bytes{history_index_table->get(last_chunk_index)};
                    if (previous_bitmap_bytes.has_value()) {
                        bm |= roaring::Roaring64Map::readSafe(byte_ptr_cast(previous_bitmap_bytes->data()),
                                                              previous_bitmap_bytes->size());
                        db_flags = 0;
                    }
                    while (bm.cardinality() > 0) {
                        auto current_chunk{db::bitmap::cut_left(bm, db::bitmap::kBitmapChunkLimit)};
                        // make chunk index
                        Bytes chunk_index(entry.key.size() + 8, '\0');
                        std::memcpy(&chunk_index[0], &entry.key[0], entry.key.size());
                        uint64_t suffix{bm.cardinality() == 0 ? UINT64_MAX : current_chunk.maximum()};
                        boost::endian::store_big_u64(&chunk_index[entry.key.size()], suffix);
                        Bytes current_chunk_bytes(current_chunk.getSizeInBytes(), '\0');
                        current_chunk.write(byte_ptr_cast(&current_chunk_bytes[0]));
                        history_index_table->put(chunk_index, current_chunk_bytes, db_flags);
                    }
                },
                db_flags, /* log_every_percent = */ 20);

            // Update progress height with last processed block
            db::stages::set_stage_progress(*txn, stage_key, block_number);
            lmdb::err_handler(txn->commit());

        } else {
            SILKWORM_LOG(LogLevel::Info) << "Nothing to process" << std::endl;
        }

        SILKWORM_LOG(LogLevel::Info) << "All Done" << std::endl;
    } catch (const std::exception &ex) {
        SILKWORM_LOG(LogLevel::Error) << ex.what() << std::endl;
        return -5;
    }
    return 0;
}
