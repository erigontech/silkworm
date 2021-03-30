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

#include <iomanip>
#include <iostream>
#include <string>
#include <unordered_map>

#include <CLI/CLI.hpp>
#include <boost/endian/conversion.hpp>
#include <boost/filesystem.hpp>
#include <thread>
#include <silkworm/common/log.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/bitmap.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/etl/collector.hpp>
#include <cbor/decoder.h>

using namespace silkworm;

constexpr size_t kBitmapBufferSizeLimit = 512 * kMebi;


void loader_function(etl::Entry entry, lmdb::Table *target_table, unsigned int db_flags) {
    auto bm{roaring::Roaring::readSafe(byte_ptr_cast(entry.value.data()), entry.value.size())};
    Bytes last_chunk_index(entry.key.size() + 4, '\0');
    std::memcpy(&last_chunk_index[0], &entry.key[0], entry.key.size());
    boost::endian::store_big_u32(&last_chunk_index[entry.key.size()], UINT32_MAX);
    auto previous_bitmap_bytes{target_table->get(last_chunk_index)};
    if (previous_bitmap_bytes.has_value()) {
        bm |= roaring::Roaring::readSafe(byte_ptr_cast(previous_bitmap_bytes->data()),
                                                previous_bitmap_bytes->size());
        db_flags = 0;
    }
    while (bm.cardinality() > 0) {
        auto current_chunk{db::bitmap::cut_left(bm, db::bitmap::kBitmapChunkLimit)};
        // make chunk index
        Bytes chunk_index(entry.key.size() + 4, '\0');
        std::memcpy(&chunk_index[0], &entry.key[0], entry.key.size());
        uint64_t suffix{bm.cardinality() == 0 ? UINT32_MAX : current_chunk.maximum()};
        boost::endian::store_big_u32(&chunk_index[entry.key.size()], suffix);
        Bytes current_chunk_bytes(current_chunk.getSizeInBytes(), '\0');
        current_chunk.write(byte_ptr_cast(&current_chunk_bytes[0]));
        target_table->put(chunk_index, current_chunk_bytes, db_flags);
    }
}

class listener_log_index : public cbor::listener {
    public:
    listener_log_index(uint64_t block_number, std::unordered_map<std::string, roaring::Roaring> * topics_map,
                std::unordered_map<std::string, roaring::Roaring> * addrs_map, uint64_t * allocated_topics, uint64_t * allocated_addrs_): 
                block_number_(block_number), topics_map_(topics_map), addrs_map_(addrs_map), allocated_topics_(allocated_topics), allocated_addrs_(allocated_addrs_) {};

    virtual void on_integer(int){};

    virtual void on_bytes(unsigned char *data, int size) {
        std::string key(reinterpret_cast<const char *>(data), size);
        if (size == kHashLength) {
            if (topics_map_->find(key) == topics_map_->end()) {
                topics_map_->emplace(key, roaring::Roaring());
            }
            topics_map_->at(key).add(block_number_);
            *allocated_topics_ += kHashLength;
        } else if (size == kAddressLength) {
            if (addrs_map_->find(key) == addrs_map_->end()) {
                addrs_map_->emplace(key, roaring::Roaring());
            }
            addrs_map_->at(key).add(block_number_);
            *allocated_addrs_ += kAddressLength;
        }
        delete[] data;
    }

    virtual void on_string(std::string &) {};

    virtual void on_array(int) {}

    virtual void on_map(int){};

    virtual void on_tag(unsigned int){};

    virtual void on_special(unsigned int){};
    
    virtual void on_bool(bool){};
    
    virtual void on_null(){};
    
    virtual void on_undefined(){};

    virtual void on_error(const char *){};

    virtual void on_extra_integer(unsigned long long, int ){};

    virtual void on_extra_tag(unsigned long long){};

    virtual void on_extra_special(unsigned long long){};

    void set_block_number(uint64_t block_number) {
        block_number_ = block_number;
    }

    private:
        uint64_t block_number_;
        std::unordered_map<std::string, roaring::Roaring> * topics_map_;
        std::unordered_map<std::string, roaring::Roaring> * addrs_map_;
        uint64_t *allocated_topics_;
        uint64_t *allocated_addrs_;
};

void flush_bitmaps(etl::Collector& collector, std::unordered_map<std::string, roaring::Roaring>& map) {
    for (const auto &[key, bm] : map) {
        Bytes bitmap_bytes(bm.getSizeInBytes(), '\0');
        bm.write(byte_ptr_cast(bitmap_bytes.data()));
        etl::Entry entry{Bytes(byte_ptr_cast(key.c_str()), key.size()), bitmap_bytes};
        collector.collect(entry);
    }
    map.clear();
}

int main(int argc, char *argv[]) {
    namespace fs = boost::filesystem;

    CLI::App app{"Generates Log Index"};

    std::string db_path{db::default_path()};
    bool full;
    app.add_option("--chaindata", db_path, "Path to a database populated by Turbo-Geth", true)
        ->check(CLI::ExistingDirectory);

    app.add_flag("--full", full, "Start making history indexes from block 0");

    CLI11_PARSE(app, argc, argv);

    // Check data.mdb exists in provided directory
    fs::path db_file{fs::path(db_path) / fs::path("data.mdb")};
    if (!fs::exists(db_file)) {
        SILKWORM_LOG(LogError) << "Can't find a valid TG data file in " << db_path << std::endl;
        return -1;
    }
    fs::path datadir(db_path);
    fs::path etl_path(datadir.parent_path() / fs::path("etl-temp"));
    fs::create_directories(etl_path);
    etl::Collector topic_collector(etl_path.string().c_str(), /* flush size */ 256 * kMebi);
    etl::Collector addresses_collector(etl_path.string().c_str(), /* flush size */ 256 * kMebi);

    lmdb::DatabaseConfig db_config{db_path};
    db_config.set_readonly(false);
    std::shared_ptr<lmdb::Environment> env{lmdb::get_env(db_config)};
    std::unique_ptr<lmdb::Transaction> txn{env->begin_rw_transaction()};
    // We take data from header table and transform it and put it in blockhashes table
    auto log_table{txn->open(db::table::kLogs)};

    try {
        auto last_processed_block_number{db::stages::get_stage_progress(*txn, db::stages::kLogIndexKey)};

        if (full) {
            last_processed_block_number = 0;
            txn->open(db::table::kLogTopicIndex, MDB_CREATE)->clear();
            txn->open(db::table::kLogAddressIndex, MDB_CREATE)->clear();
        }

        // Extract
        Bytes start(8, '\0');
        boost::endian::store_big_u64(&start[0], last_processed_block_number);
        MDB_val mdb_key{db::to_mdb_val(start)};
        MDB_val mdb_data;

        SILKWORM_LOG(LogInfo) << "Started Log Index Extraction" << std::endl;

        uint64_t block_number{0};
        uint64_t topics_allocated_space{0};
        uint64_t addrs_allocated_space{0};
        std::unordered_map<std::string, roaring::Roaring> topic_bitmaps;
        std::unordered_map<std::string, roaring::Roaring> addresses_bitmaps;
        listener_log_index current_listener(block_number, &topic_bitmaps, &addresses_bitmaps, &topics_allocated_space, &addrs_allocated_space);
        int rc{log_table->seek(&mdb_key, &mdb_data)};  // Sets cursor to nearest key greater equal than this
        while (!rc) {                                        /* Loop as long as we have no errors*/
            block_number = boost::endian::load_big_u64(static_cast<uint8_t*>(mdb_key.mv_data));
            current_listener.set_block_number(block_number);
            cbor::input input(static_cast<uint8_t*>(mdb_data.mv_data), mdb_data.mv_size);
            cbor::decoder decoder(input, current_listener);
            decoder.run();
            if (topics_allocated_space > kBitmapBufferSizeLimit) {
                flush_bitmaps(topic_collector, topic_bitmaps);
                SILKWORM_LOG(LogInfo) << "Current Block: " << block_number << std::endl;
                topics_allocated_space = 0;
            }

            if (addrs_allocated_space > kBitmapBufferSizeLimit) {
                flush_bitmaps(addresses_collector, addresses_bitmaps);
                SILKWORM_LOG(LogInfo) << "Current Block: " << block_number << std::endl;
                addrs_allocated_space = 0;
            }
    
            rc = log_table->get_next(&mdb_key, &mdb_data);
        }

        if (rc && rc != MDB_NOTFOUND) { /* MDB_NOTFOUND is not actually an error rather eof */
            lmdb::err_handler(rc);
        }

        flush_bitmaps(topic_collector, topic_bitmaps);
        flush_bitmaps(addresses_collector, addresses_bitmaps);

        SILKWORM_LOG(LogInfo) << "Latest Block: " << block_number << std::endl;
        // Proceed only if we've done something
        SILKWORM_LOG(LogInfo) << "Started Topics Loading" << std::endl;
        // if stage has never been touched then appending is safe
        unsigned int db_flags{last_processed_block_number ? 0u : MDB_APPEND};

        // Eventually load collected items WITH transform (may throw)
        topic_collector.load(txn->open(db::table::kLogTopicIndex, MDB_CREATE).get(), loader_function, db_flags, /* log_every_percent = */ 10);
        SILKWORM_LOG(LogInfo) << "Started Address Loading" << std::endl;
        addresses_collector.load(txn->open(db::table::kLogAddressIndex, MDB_CREATE).get(), loader_function, db_flags, /* log_every_percent = */ 10);

        // Update progress height with last processed block
        db::stages::set_stage_progress(*txn, db::stages::kLogIndexKey, block_number);
        lmdb::err_handler(txn->commit());
        txn.reset();
        SILKWORM_LOG(LogInfo) << "All Done" << std::endl;
    } catch (const std::exception &ex) {
        SILKWORM_LOG(LogError) << ex.what() << std::endl;
        return -5;
    }
    return 0;
}
