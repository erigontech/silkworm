/*
   Copyright 2021-2022 The Silkworm Authors

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

#include "stage_history_index.hpp"

#include <unordered_map>

#include <silkworm/common/cast.hpp>
#include <silkworm/common/endian.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/db/bitmap.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/etl/collector.hpp>

#include "stagedsync.hpp"

namespace silkworm::stagedsync {

StageResult HistoryIndex::forward(db::RWTxn& txn) {
    try {
        throw_if_stopping();

        // Check stage boundaries from previous execution and previous stage execution
        const auto previous_progress{get_progress(txn)};
        const auto previous_progress_accounts{
            db::stages::read_stage_progress(*txn, db::stages::kAccountHistoryIndexKey)};
        const auto previous_progress_storage{
            db::stages::read_stage_progress(*txn, db::stages::kStorageHistoryIndexKey)};
        const auto execution_stage_progress{db::stages::read_stage_progress(*txn, db::stages::kExecutionKey)};
        if (previous_progress == execution_stage_progress) {
            // Nothing to process
            return StageResult::kSuccess;
        } else if (previous_progress > execution_stage_progress) {
            // Something bad had happened.  Maybe we need to unwind ?
            throw StageError(StageResult::kInvalidProgress,
                             "HistoryIndex progress " + std::to_string(previous_progress) +
                                 " greater than Execution progress " + std::to_string(execution_stage_progress));
        }

        reset_log_progress();
        const BlockNum segment_width{execution_stage_progress - previous_progress};
        if (segment_width > 16) {
            log::Info("Begin " + std::string(stage_name_),
                      {"op", std::string(magic_enum::enum_name<OperationType>(OperationType::Forward)), "from",
                       std::to_string(previous_progress), "to", std::to_string(execution_stage_progress), "span",
                       std::to_string(segment_width)});
        }

        collector_ = std::make_unique<etl::Collector>(node_settings_);

        if (!previous_progress_accounts || previous_progress_accounts < previous_progress)
            success_or_throw(forward_impl(txn, previous_progress_accounts, execution_stage_progress, false));
        if (!previous_progress_storage || previous_progress_storage < previous_progress)
            success_or_throw(forward_impl(txn, previous_progress_storage, execution_stage_progress, true));

        collector_.reset();
        reset_log_progress();
        update_progress(txn, execution_stage_progress);
        txn.commit();

    } catch (const StageError& ex) {
        log::Error(std::string(stage_name_),
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        collector_.reset();
        return static_cast<StageResult>(ex.err());
    } catch (const std::exception& ex) {
        collector_.reset();
        log::Error(std::string(stage_name_), {"exception", std::string(ex.what())});
        return StageResult::kUnexpectedError;
    }

    operation_ = OperationType::None;
    return is_stopping() ? StageResult::kAborted : StageResult::kSuccess;
}

StageResult HistoryIndex::unwind(db::RWTxn& txn, BlockNum to) {
    try {
        throw_if_stopping();

        // Check stage boundaries from previous execution and previous stage execution
        const auto previous_progress{get_progress(txn)};
        const auto previous_progress_accounts{
            db::stages::read_stage_progress(*txn, db::stages::kAccountHistoryIndexKey)};
        const auto previous_progress_storage{
            db::stages::read_stage_progress(*txn, db::stages::kStorageHistoryIndexKey)};
        const auto execution_stage_progress{db::stages::read_stage_progress(*txn, db::stages::kExecutionKey)};
        if (previous_progress <= to || execution_stage_progress <= to) {
            // Nothing to process
            return StageResult::kSuccess;
        }

        reset_log_progress();
        const BlockNum segment_width{previous_progress - to};
        if (segment_width > 16) {
            log::Info(
                "Begin " + std::string(stage_name_),
                {"op", std::string(magic_enum::enum_name<OperationType>(OperationType::Unwind)), "from",
                 std::to_string(previous_progress), "to", std::to_string(to), "span", std::to_string(segment_width)});
        }

        collector_ = std::make_unique<etl::Collector>(node_settings_);

        if (previous_progress_accounts && previous_progress_accounts > to)
            success_or_throw(unwind_impl(txn, previous_progress_accounts, to, false));
        if (previous_progress_storage && previous_progress_storage > to)
            success_or_throw(unwind_impl(txn, previous_progress_storage, to, true));

        collector_.reset();
        reset_log_progress();
        update_progress(txn, to);
        txn.commit();

    } catch (const StageError& ex) {
        log::Error(std::string(stage_name_),
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        collector_.reset();
        return static_cast<StageResult>(ex.err());
    } catch (const std::exception& ex) {
        collector_.reset();
        log::Error(std::string(stage_name_), {"exception", std::string(ex.what())});
        return StageResult::kUnexpectedError;
    }

    operation_ = OperationType::None;
    return is_stopping() ? StageResult::kAborted : StageResult::kSuccess;
}

StageResult HistoryIndex::prune(db::RWTxn& txn) {
    try {
        throw_if_stopping();
        if (!node_settings_->prune_mode->history().enabled()) return StageResult::kSuccess;

        const auto forward_progress{get_progress(txn)};
        const auto prune_progress{get_prune_progress(txn)};
        if (prune_progress >= forward_progress) {
            return StageResult::kSuccess;
        }

        // Need to erase all history info below this threshold
        // If threshold is zero we don't have anything to prune
        const auto prune_threshold{node_settings_->prune_mode->history().value_from_head(forward_progress)};
        if (!prune_threshold) return StageResult::kSuccess;

        reset_log_progress();
        const BlockNum segment_width{forward_progress - prune_progress};
        if (segment_width > 16) {
            log::Info("Begin " + std::string(stage_name_),
                      {"op", std::string(magic_enum::enum_name<OperationType>(OperationType::Unwind)), "from",
                       std::to_string(prune_progress), "to", std::to_string(forward_progress), "span",
                       std::to_string(segment_width)});
        }

        // We split the stage in two
        const auto prune_progress_accounts{
            db::stages::read_stage_prune_progress(*txn, db::stages::kAccountHistoryIndexKey)};
        const auto prune_progress_storage{
            db::stages::read_stage_prune_progress(*txn, db::stages::kAccountHistoryIndexKey)};

    } catch (const StageError& ex) {
        log::Error() << "Unexpected db error in " << std::string(__FUNCTION__) << " : " << ex.what();
        return magic_enum::enum_value<StageResult>(ex.err());
    } catch (const mdbx::exception& ex) {
        log::Error() << "Unexpected db error in " << std::string(__FUNCTION__) << " : " << ex.what();
        return StageResult::kDbError;
    } catch (...) {
        log::Error() << "Unexpected unknown error in " << std::string(__FUNCTION__);
        return StageResult::kUnexpectedError;
    }
}

StageResult HistoryIndex::forward_impl(db::RWTxn& txn, const BlockNum from, const BlockNum to, const bool storage) {
    const db::MapConfig source_config{storage ? db::table::kStorageChangeSet : db::table::kAccountChangeSet};
    const db::MapConfig target_config{storage ? db::table::kStorageHistory : db::table::kAccountHistory};

    std::unique_lock log_lck(sl_mutex_);
    operation_ = OperationType::Forward;
    loading_ = false;
    current_source_ = std::string(source_config.name);
    current_target_ = std::string(target_config.name);
    current_key_.clear();
    log_lck.unlock();

    collect_bitmaps_from_changeset(txn, source_config, from, to, storage);

    if (!collector_->empty()) {
        log_lck.lock();
        loading_ = true;
        log_lck.unlock();
        db::Cursor target(txn, target_config);
        MDBX_put_flags_t db_flags{target.empty() ? MDBX_put_flags_t::MDBX_APPEND : MDBX_put_flags_t::MDBX_UPSERT};

        // Collected bitmaps must be merged with the last uncompleted shard for each key
        etl::LoadFunc load_func{[](const etl::Entry& entry, mdbx::cursor& index_cursor, MDBX_put_flags_t put_flags) {
            auto bitmap{roaring::Roaring64Map::readSafe(byte_ptr_cast(entry.value.data()), entry.value.size())};

            // Check whether we still need to rework the previous entry
            Bytes chunk_key{entry.key};
            chunk_key.append(db::block_key(UINT64_MAX));  // The highest uncompleted chunk

            if (put_flags != MDBX_put_flags_t::MDBX_APPEND) {
                auto index_data{index_cursor.find(db::to_slice(chunk_key), false)};
                if (index_data) {
                    // Merge previous and current bitmap
                    bitmap |= roaring::Roaring64Map::readSafe(index_data.value.char_ptr(), index_data.value.length());
                    index_cursor.erase();  // Delete currently found record as it'll be rewritten
                }
            }

            // Consume the bitmap splitting it in chunks
            while (!bitmap.isEmpty()) {
                auto bitmap_chunk{db::bitmap::cut_left(bitmap, db::bitmap::kBitmapChunkLimit)};
                const BlockNum suffix{bitmap.isEmpty() /* consumed to last chunk */ ? UINT64_MAX
                                                                                    : bitmap_chunk.maximum()};
                endian::store_big_u64(&chunk_key[chunk_key.size() - sizeof(BlockNum)], suffix);

                // Push chunk to database
                Bytes chunk_bytes(bitmap_chunk.getSizeInBytes(), '\0');
                bitmap_chunk.write(byte_ptr_cast(&chunk_bytes[0]));
                mdbx::slice k{db::to_slice(chunk_key)};
                mdbx::slice v{db::to_slice(chunk_bytes)};
                mdbx::error::success_or_throw(index_cursor.put(k, &v, put_flags));
            }
        }};
        collector_->load(target, load_func, db_flags);
        collector_->clear();
    }

    db::stages::write_stage_progress(
        *txn, (storage ? db::stages::kStorageHistoryIndexKey : db::stages::kAccountHistoryIndexKey), to);

    return StageResult::kSuccess;
}

StageResult HistoryIndex::unwind_impl(db::RWTxn& txn, const BlockNum from, const BlockNum to, const bool storage) {
    using namespace std::chrono_literals;
    auto log_time{std::chrono::steady_clock::now()};

    const db::MapConfig source_config{storage ? db::table::kStorageChangeSet : db::table::kAccountChangeSet};
    const db::MapConfig target_config{storage ? db::table::kStorageHistory : db::table::kAccountHistory};

    std::unique_lock log_lck(sl_mutex_);
    operation_ = OperationType::Unwind;
    loading_ = false;
    current_source_ = std::string(source_config.name);
    current_target_ = std::string(target_config.name);
    current_key_.clear();
    log_lck.unlock();

    // Create a bitmap holding range of blocks to be unwound (the subtrahend)
    const auto subtrahend_bitmap{roaring::Roaring64Map(roaring::api::roaring_bitmap_from_range(to + 1, from, 1))};

    db::Cursor target(txn, target_config);
    const auto keys{collect_unique_keys_from_changeset(txn, source_config, from, to, storage)};
    for (const auto& [key, created] : keys) {
        // Log and abort check
        if (auto now{std::chrono::steady_clock::now()}; log_time <= now) {
            throw_if_stopping();
            log_lck.lock();
            current_key_ = abridge(to_hex(key, true), kAddressLength + 2);
            log_time = now + 5s;
            log_lck.unlock();
        }

        if (created) {
            // Key was created in the batch we're unwinding
            // Delete all its history
            db::cursor_for_prefix(target, db::to_slice(key), db::walk_erase);
            continue;
        }

        // Locate previous incomplete shard. There's always one if account has been touched at least once in
        // changeset !
        Bytes shard_key{key};
        shard_key.append(db::block_key(UINT64_MAX));
        auto index_data{target.find(db::to_slice(shard_key), false)};
        while (index_data) {
            const auto index_data_key_view{db::from_slice(index_data.key)};
            if (!index_data_key_view.starts_with(key)) {
                break;
            }

            auto db_bitmap{roaring::Roaring64Map::readSafe(index_data.value.char_ptr(), index_data.value.length())};
            db_bitmap -= subtrahend_bitmap;
            if (db_bitmap.isEmpty()) {
                // Delete this record and move to previous shard
                target.erase();
                index_data = target.to_previous(false);
                continue;
            }

            // Replace current record with the new bitmap ensuring is marked as last shard
            Bytes shard_bytes(db_bitmap.getSizeInBytes(), '\0');
            db_bitmap.write(byte_ptr_cast(&shard_bytes[0]));
            auto shard_bytes_slice{db::to_slice(shard_bytes)};
            mdbx::error::success_or_throw(
                target.put(db::to_slice(shard_key), &shard_bytes_slice, MDBX_put_flags_t::MDBX_CURRENT));

            break;
        }
    }

    db::stages::write_stage_progress(
        *txn, (storage ? db::stages::kStorageHistoryIndexKey : db::stages::kAccountHistoryIndexKey), to);

    return StageResult::kSuccess;
}

StageResult HistoryIndex::prune_impl(db::RWTxn& txn, const BlockNum threshold, const BlockNum to, const bool storage) {
    using namespace std::chrono_literals;
    auto log_time{std::chrono::steady_clock::now()};

    const db::MapConfig table_config{storage ? db::table::kStorageChangeSet : db::table::kAccountChangeSet};

    std::unique_lock log_lck(sl_mutex_);
    operation_ = OperationType::Prune;
    loading_ = false;
    current_source_ = std::string(table_config.name);
    current_target_ = current_source_;
    current_key_.clear();
    log_lck.unlock();

    db::Cursor table(txn, table_config);
    auto data{table.to_first(false)};
    while (data) {
        auto data_key_view{db::from_slice(data.key)};

        // Log and abort check
        if (auto now{std::chrono::steady_clock::now()}; log_time <= now) {
            throw_if_stopping();
            log_lck.lock();
            current_key_ = abridge(to_hex(data_key_view, true), kAddressLength + 2);
            log_time = now + 5s;
            log_lck.unlock();
        }

        // Suffix indicates the upper bound of the shard.
        auto suffix{endian::load_big_u64(&data_key_view[data_key_view.size() - sizeof(BlockNum)])};

        // If below pruning threshold simply delete the record
        if (suffix <= threshold) {
            table.erase();
        } else {
            // Read current bitmap
            auto bitmap{roaring::Roaring64Map::readSafe(data.value.char_ptr(), data.value.length())};
            if (bitmap.minimum() <= threshold) {
                // Build list of blocks to be pruned inside this shard
                const auto subtrahend_bitmap{
                    roaring::Roaring64Map(roaring::api::roaring_bitmap_from_range(bitmap.minimum(), threshold, 1))};
                bitmap -= subtrahend_bitmap;  // and remove them

                // Replace with new data or delete
                if (!bitmap.isEmpty()) {
                    Bytes new_shard_data(bitmap.getSizeInBytes(), '\0');
                    bitmap.write(byte_ptr_cast(&new_shard_data[0]));
                    auto new_shard_slice{db::to_slice(new_shard_data)};
                    mdbx::error::success_or_throw(
                        table.put(db::to_slice(data_key_view), &new_shard_slice, MDBX_put_flags_t::MDBX_CURRENT));
                } else {
                    table.erase();
                }
            }
        }
    }

    db::stages::write_stage_prune_progress(
        *txn, (storage ? db::stages::kStorageHistoryIndexKey : db::stages::kAccountHistoryIndexKey), to);

    return StageResult::kSuccess;
}

void HistoryIndex::collect_bitmaps_from_changeset(db::RWTxn& txn, const db::MapConfig& source_config,
                                                  const BlockNum from, const BlockNum to, bool storage) {
    using namespace std::chrono_literals;
    auto log_time{std::chrono::steady_clock::now()};

    std::unordered_map<Bytes, roaring::Roaring64Map, boost::hash<Bytes>> bitmaps;
    auto bitmaps_it{bitmaps.begin()};
    Bytes bitmaps_key{};
    size_t bitmaps_size{0};

    auto bitmaps_flush{[&bitmaps, &bitmaps_size](etl::Collector* collector) {
        for (const auto& [key, bitmap] : bitmaps) {
            Bytes bitmap_data(bitmap.getSizeInBytes(), '\0');
            bitmap.write(byte_ptr_cast(bitmap_data.data()));
            collector->collect({key, bitmap_data});
        }
        bitmaps.clear();
        bitmaps_size = 0;
    }};

    BlockNum expected_block_number{std::min(from, to) + 1};
    const BlockNum max_block_number{std::max(from, to)};
    BlockNum reached_block_number{0};

    auto start_key{db::block_key(expected_block_number)};
    db::Cursor source(txn, source_config);
    auto source_data{storage ? source.lower_bound(db::to_slice(start_key), false)
                             : source.find(db::to_slice(start_key), false)};
    while (source_data) {
        auto source_data_key_view{db::from_slice(source_data.key)};
        reached_block_number = endian::load_big_u64(source_data_key_view.data());
        check_block_sequence(expected_block_number, reached_block_number);
        if (reached_block_number > max_block_number) {
            break;
        }
        source_data_key_view.remove_prefix(sizeof(BlockNum));

        // Log and abort check
        if (auto now{std::chrono::steady_clock::now()}; log_time <= now) {
            throw_if_stopping();
            std::unique_lock log_lck(sl_mutex_);
            current_key_ = std::to_string(reached_block_number);
            log_time = now + 5s;
        }

        while (source_data) {
            auto source_data_value_view{db::from_slice(source_data.value)};
            if (storage) {
                // Contract address + incarnation + location
                bitmaps_key.assign(source_data_key_view).append(source_data_value_view.substr(0, kHashLength));
            } else {
                // Only address for accounts
                bitmaps_key.assign(source_data_value_view.substr(0, kAddressLength));
            }

            bitmaps_it = bitmaps.find(bitmaps_key);
            if (bitmaps_it == bitmaps.end()) {
                bitmaps_it = bitmaps.emplace(bitmaps_key, roaring::Roaring64Map()).first;
                bitmaps_size += bitmaps_key.size();
            }
            bitmaps_it->second.add(reached_block_number);
            bitmaps_size += sizeof(BlockNum);

            source_data = source.to_current_next_multi(false);
        }

        // Flush bitmaps to etl if necessary
        if (bitmaps_size >= kBitmapBufferSizeLimit) {
            bitmaps_flush(collector_.get());
        }

        ++expected_block_number;
        source_data = source.to_next(false);
    }

    if (bitmaps_size) {
        bitmaps_flush(collector_.get());
    }
}

std::unordered_map<Bytes, bool, boost::hash<Bytes>> HistoryIndex::collect_unique_keys_from_changeset(
    db::RWTxn& txn, const db::MapConfig& source_config, BlockNum from, BlockNum to, bool storage) {
    using namespace std::chrono_literals;
    auto log_time{std::chrono::steady_clock::now()};

    std::unordered_map<Bytes, bool, boost::hash<Bytes>> ret;
    Bytes unique_key{};

    BlockNum expected_block_number{std::min(from, to) + 1};
    const BlockNum max_block_number{std::max(from, to)};
    BlockNum reached_block_number{0};

    auto start_key{db::block_key(expected_block_number)};
    db::Cursor source(txn, source_config);
    auto source_data{storage ? source.lower_bound(db::to_slice(start_key), false)
                             : source.find(db::to_slice(start_key), false)};

    while (source_data) {
        auto source_data_key_view{db::from_slice(source_data.key)};
        reached_block_number = endian::load_big_u64(source_data_key_view.data());
        check_block_sequence(expected_block_number, reached_block_number);
        if (reached_block_number > max_block_number) {
            break;
        }
        source_data_key_view.remove_prefix(sizeof(BlockNum));

        // Log and abort check
        if (auto now{std::chrono::steady_clock::now()}; log_time <= now) {
            throw_if_stopping();
            std::unique_lock log_lck(sl_mutex_);
            current_key_ = std::to_string(reached_block_number);
            log_time = now + 5s;
        }

        while (source_data) {
            auto source_data_value_view{db::from_slice(source_data.value)};
            if (storage) {
                // Contract address + incarnation + location
                unique_key.assign(source_data_key_view).append(source_data_value_view.substr(0, kHashLength));
                source_data_value_view.remove_prefix(kHashLength);
            } else {
                // Only address for accounts
                unique_key.assign(source_data_value_view.substr(0, kAddressLength));
                source_data_value_view.remove_prefix(kAddressLength);
            }
            if (!ret.contains(unique_key)) {
                (void)ret.emplace(unique_key, source_data_value_view.empty());
            }
            source_data = source.to_current_next_multi(false);
        }

        ++expected_block_number;
        source_data = source.to_next(false);
    }

    return ret;
}

std::vector<std::string> HistoryIndex::get_log_progress() {
    std::vector<std::string> ret{};
    std::unique_lock log_lck(sl_mutex_);
    if (current_source_.empty() && current_target_.empty()) {
        ret.insert(ret.end(), {"db", "waiting ..."});
    } else {
        if (operation_ == OperationType::Forward || operation_ == OperationType::Unwind) {
            if (loading_) {
                current_key_ = collector_ ? collector_->get_load_key() : "";
                ret.insert(ret.end(), {"from", "etl", "to", current_target_, "key", current_key_});
            } else {
                ret.insert(ret.end(), {"from", current_source_, "to", "etl", "key", current_key_});
            }
        } else {
            ret.insert(ret.end(), {"from", current_source_, "key", current_key_});
        }
    }
    return ret;
}

void HistoryIndex::reset_log_progress() {
    std::unique_lock log_lck(sl_mutex_);
    operation_ = OperationType::None;
    loading_ = false;
    current_source_.clear();
    current_target_.clear();
    current_key_.clear();
}

static constexpr size_t kBitmapBufferSizeLimit = 256_Mebi;

namespace fs = std::filesystem;

static StageResult history_index_stage(db::RWTxn& txn, const std::filesystem::path& etl_path, bool storage) {
    fs::create_directories(etl_path);

    etl::Collector collector(etl_path, /* flush size */ 512_Mebi);
    std::unordered_map<std::string, roaring::Roaring64Map> bitmaps;

    auto flush_bitmaps_to_etl = [&collector, &bitmaps] {
        for (const auto& [bitmap_key, bitmap] : bitmaps) {
            Bytes bitmap_bytes(bitmap.getSizeInBytes(), '\0');
            bitmap.write(byte_ptr_cast(bitmap_bytes.data()));
            collector.collect(etl::Entry{Bytes(byte_ptr_cast(bitmap_key.c_str()), bitmap_key.size()), bitmap_bytes});
        }
        bitmaps.clear();
    };

    // We take data from change-sets and turn it to indexes, so from [Block Number => Location] to [Location => Block
    // Number]
    db::MapConfig changeset_config = storage ? db::table::kStorageChangeSet : db::table::kAccountChangeSet;
    db::MapConfig index_config = storage ? db::table::kStorageHistory : db::table::kAccountHistory;
    const char* stage_key = storage ? db::stages::kStorageHistoryIndexKey : db::stages::kAccountHistoryIndexKey;

    auto changeset_table{db::open_cursor(*txn, changeset_config)};
    auto last_processed_block_number{db::stages::read_stage_progress(*txn, stage_key)};
    Bytes start{db::block_key(last_processed_block_number + 1)};

    // Extract
    log::Info() << "Started " << (storage ? "Storage" : "Account")
                << " Index Extraction. From: " << (last_processed_block_number + 1);

    size_t allocated_space{0};
    BlockNum block_number{0};
    auto data{changeset_table.lower_bound(db::to_slice(start))};
    while (data) {
        std::string composite_key;
        auto key{db::from_slice(data.key)};
        auto value{db::from_slice(data.value)};
        auto [db_key, _]{db::changeset_to_plainstate_format(key, value)};
        // Make the composite key accordingly whether we are dealing with storages or accounts
        if (storage) {
            // Storage: Address + Location
            composite_key.resize(kAddressLength + kHashLength);
            std::memcpy(&composite_key[0], &db_key[0], kAddressLength);
            std::memcpy(&composite_key[kAddressLength], &db_key[kAddressLength + db::kIncarnationLength], kHashLength);
        } else {
            // Account: Address
            composite_key = std::string(data.value.char_ptr(), kAddressLength);
        }
        // Initialize composite key if needed
        if (bitmaps.find(composite_key) == bitmaps.end()) {
            bitmaps.emplace(composite_key, roaring::Roaring64Map());
        }
        // Add block number to the bitmap of current key
        block_number = endian::load_big_u64(static_cast<uint8_t*>(data.key.data()));
        bitmaps.at(composite_key).add(block_number);
        allocated_space += 8;
        // Flush to ETL
        if (64 * bitmaps.size() + allocated_space > kBitmapBufferSizeLimit) {
            flush_bitmaps_to_etl();
            allocated_space = 0;
            log::Info() << "Current Block: " << block_number;
        }
        data = changeset_table.to_next(/*throw_notfound*/ false);
    }
    changeset_table.close();
    if (allocated_space != 0) {
        flush_bitmaps_to_etl();
    }

    log::Info() << "Latest Block: " << block_number;

    // Proceed only if we've done something
    if (!collector.empty()) {
        log::Info() << "Started Loading";

        MDBX_put_flags_t db_flags{last_processed_block_number ? MDBX_put_flags_t::MDBX_UPSERT
                                                              : MDBX_put_flags_t::MDBX_APPEND};

        // Eventually load collected items WITH transform (may throw)
        auto target{db::open_cursor(*txn, index_config)};
        collector.load(
            target,
            [](const etl::Entry& entry, mdbx::cursor& history_index_table, MDBX_put_flags_t put_flags) {
                auto bm{roaring::Roaring64Map::readSafe(byte_ptr_cast(entry.value.data()), entry.value.size())};
                // Check whether we still need to rework the previous entry
                Bytes last_chunk_index(entry.key.size() + 8, '\0');
                std::memcpy(&last_chunk_index[0], &entry.key[0], entry.key.size());
                endian::store_big_u64(&last_chunk_index[entry.key.size()], UINT64_MAX);
                auto previous_bitmap_bytes{history_index_table.find(db::to_slice(last_chunk_index), false)};
                // If we have an unfinished bitmap for the current location then continue working on it
                if (previous_bitmap_bytes) {
                    // Merge previous and current bitmap
                    bm |= roaring::Roaring64Map::readSafe(previous_bitmap_bytes.value.char_ptr(),
                                                          previous_bitmap_bytes.value.length());
                    put_flags = MDBX_put_flags_t::MDBX_UPSERT;
                }
                while (bm.cardinality() > 0) {
                    // Divide in different bitmaps of different (chunks) and push all of them individually
                    auto current_chunk{db::bitmap::cut_left(bm, db::bitmap::kBitmapChunkLimit)};
                    // Make chunk index (Location + Suffix )
                    Bytes chunk_index(entry.key.size() + 8, '\0');
                    std::memcpy(&chunk_index[0], &entry.key[0], entry.key.size());
                    // Suffix is either the maximum Block Number of the bitmap or if it's the last chunk: UINT64_MAX
                    BlockNum suffix{bm.cardinality() == 0 ? UINT64_MAX : current_chunk.maximum()};
                    endian::store_big_u64(&chunk_index[entry.key.size()], suffix);
                    // Push chunk to database
                    Bytes current_chunk_bytes(current_chunk.getSizeInBytes(), '\0');
                    current_chunk.write(byte_ptr_cast(&current_chunk_bytes[0]));
                    mdbx::slice k{db::to_slice(chunk_index)};
                    mdbx::slice v{db::to_slice(current_chunk_bytes)};
                    mdbx::error::success_or_throw(history_index_table.put(k, &v, put_flags));
                }
            },
            db_flags);

        // Update progress height with last processed block
        db::stages::write_stage_progress(*txn, stage_key, block_number);
        txn.commit();

    } else {
        log::Info() << "Nothing to process";
    }

    log::Info() << "All Done";

    return StageResult::kSuccess;
}

StageResult history_index_unwind(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t unwind_to,
                                 bool storage) {
    // We take data from header table and transform it and put it in blockhashes table
    db::MapConfig index_config = storage ? db::table::kStorageHistory : db::table::kAccountHistory;
    const char* stage_key = storage ? db::stages::kStorageHistoryIndexKey : db::stages::kAccountHistoryIndexKey;
    etl::Collector collector(etl_path,
                             /* flush size */ 10_Mebi);  // We do not unwind by many blocks usually

    auto index_table{db::open_cursor(*txn, index_config)};
    // Extract
    log::Info() << "Started " << (storage ? "Storage" : "Account") << " Index Unwind";
    if (index_table.to_first(/* throw_notfound = */ false)) {
        auto data{index_table.current()};
        while (data) {
            // Get bitmap data of current element
            auto key{db::from_slice(data.key)};
            auto bitmap_data{db::from_slice(data.value)};
            auto bm{roaring::Roaring64Map::readSafe(byte_ptr_cast(bitmap_data.data()), bitmap_data.size())};
            // Check whether we should skip the current bitmap
            if (bm.maximum() <= unwind_to) {
                data = index_table.to_next(/*throw_notfound*/ false);
                continue;
            }
            // check if unwind can be applied
            if (bm.minimum() <= unwind_to) {
                // Erase elements that are > unwind_to
                bm &= roaring::Roaring64Map(roaring::api::roaring_bitmap_from_range(0, unwind_to + 1, 1));
                Bytes new_bitmap(bm.getSizeInBytes(), '\0');
                bm.write(byte_ptr_cast(&new_bitmap[0]));
                // generates new key
                Bytes new_key(key.size(), '\0');
                std::memcpy(&new_key[0], key.data(), key.size());
                endian::store_big_u32(&new_key[new_key.size() - 4], UINT32_MAX);
                // replace with new index
                collector.collect(etl::Entry{new_key, new_bitmap});
            }
            index_table.erase(/* whole_multivalue = */ true);
            data = index_table.to_next(/*throw_notfound*/ false);
        }
    }

    db::stages::write_stage_progress(*txn, stage_key, unwind_to);
    collector.load(index_table, nullptr, MDBX_put_flags_t::MDBX_UPSERT);
    txn.commit();
    log::Info() << "All Done";

    return StageResult::kSuccess;
}

StageResult history_index_prune(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t prune_from,
                                bool storage) {
    db::MapConfig index_config = storage ? db::table::kStorageHistory : db::table::kAccountHistory;
    const char* stage_key = storage ? db::stages::kStorageHistoryIndexKey : db::stages::kAccountHistoryIndexKey;
    etl::Collector collector(etl_path.string().c_str(),
                             /* flush size */ 10 * kMebi);  // We do not prune many blocks usually

    auto last_processed_block{db::stages::read_stage_progress(*txn, stage_key)};

    auto index_table{db::open_cursor(*txn, index_config)};
    log::Info() << "Pruning " << (storage ? "Storage" : "Account") << " History from: " << prune_from;

    if (index_table.to_first(/* throw_notfound = */ false)) {
        auto data{index_table.current()};
        while (data) {
            // Get bitmap data of current element
            auto key{db::from_slice(data.key)};
            auto bitmap_data{db::from_slice(data.value)};
            auto bm{roaring::Roaring64Map::readSafe(byte_ptr_cast(bitmap_data.data()), bitmap_data.size())};
            // Check whether we should skip the current bitmap
            if (bm.minimum() >= prune_from) {
                data = index_table.to_next(/*throw_notfound*/ false);
                continue;
            }
            // check if prune can be applied
            if (bm.maximum() >= prune_from) {
                // Erase elements that are below prune_from
                bm &= roaring::Roaring64Map(
                    roaring::api::roaring_bitmap_from_range(prune_from, last_processed_block + 1, 1));
                Bytes new_bitmap(bm.getSizeInBytes(), '\0');
                bm.write(byte_ptr_cast(&new_bitmap[0]));
                // replace with new index
                etl::Entry entry{Bytes{key}, new_bitmap};
                collector.collect(entry);
            }
            index_table.erase(/* whole_multivalue = */ true);
            data = index_table.to_next(/*throw_notfound*/ false);
        }
    }

    collector.load(index_table, nullptr, MDBX_put_flags_t::MDBX_UPSERT);
    txn.commit();
    log::Info() << "Pruning " << (storage ? "Storage" : "Account") << " History finished...";

    return StageResult::kSuccess;
}

StageResult stage_account_history(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t) {
    return history_index_stage(txn, etl_path, false);
}
StageResult stage_storage_history(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t) {
    return history_index_stage(txn, etl_path, true);
}

StageResult unwind_account_history(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t unwind_to) {
    return history_index_unwind(txn, etl_path, unwind_to, false);
}

StageResult unwind_storage_history(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t unwind_to) {
    return history_index_unwind(txn, etl_path, unwind_to, true);
}

StageResult prune_account_history(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t prune_from) {
    return history_index_prune(txn, etl_path, prune_from, false);
}
StageResult prune_storage_history(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t prune_from) {
    return history_index_prune(txn, etl_path, prune_from, true);
}

}  // namespace silkworm::stagedsync
