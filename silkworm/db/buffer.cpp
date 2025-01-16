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

#include "buffer.hpp"

#include <algorithm>
#include <stdexcept>

#include <absl/container/btree_set.h>

#include <silkworm/core/common/endian.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/log_cbor.hpp>
#include <silkworm/db/receipt_cbor.hpp>
#include <silkworm/db/state/account_codec.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/common/stopwatch.hpp>

namespace silkworm::db {

using datastore::kvdb::to_slice;

template <class TFlatHashMap>
size_t flat_hash_map_memory_size(size_t capacity) {
    return sizeof(std::pair<const typename TFlatHashMap::key_type, typename TFlatHashMap::mapped_type>) * capacity;
}

static size_t flat_hash_map_capacity_for_size(size_t size, size_t current_capacity) {
    // if the desired size is less than the growth threshold, the current capacity is enough
    if (size * uint64_t{32} <= current_capacity * uint64_t{25}) {
        return current_capacity;
    }
    // otherwise the capacity needs to double up
    return current_capacity * 2;
}

template <class TFlatHashMap>
size_t flat_hash_map_memory_size_after_inserts(const TFlatHashMap& map, size_t inserts_count) {
    size_t capacity_after_inserts = flat_hash_map_capacity_for_size(map.size() + inserts_count, map.capacity());
    return flat_hash_map_memory_size<TFlatHashMap>(capacity_after_inserts);
}

void Buffer::begin_block(uint64_t block_num, size_t updated_accounts_count) {
    if (current_batch_state_size() > memory_limit_) {
        throw MemoryLimitError();
    }
    if (flat_hash_map_memory_size_after_inserts(accounts_, updated_accounts_count) > memory_limit_) {
        throw MemoryLimitError();
    }

    block_num_ = block_num;
    changed_storage_.clear();
}

void Buffer::update_account(const evmc::address& address, std::optional<Account> initial,
                            std::optional<Account> current) {
    // Skip update if both initial and final state are non-existent (i.e. contract creation+destruction within the same block)
    if (!initial && !current) {
        // Only to perfectly match Erigon state batch size (Erigon does count any account w/ old=new=empty value).
        batch_state_size_ += kAddressLength;
        return;
    }

    const bool equal{current == initial};
    const bool account_deleted{!current.has_value()};

    if (equal && !account_deleted && !changed_storage_.contains(address)) {
        // Follows the Erigon logic when to populate account changes.
        // See (ChangeSetWriter)UpdateAccountData & DeleteAccount.
        return;
    }

    if (block_num_ >= prune_history_threshold_) {
        Bytes encoded_initial{};
        if (initial) {
            bool omit_code_hash{!account_deleted};
            encoded_initial = state::AccountCodec::encode_for_storage(*initial, omit_code_hash);
        }

        block_account_changes_[block_num_].insert_or_assign(address, encoded_initial);
    }

    size_t encoding_length_for_storage = current ? state::AccountCodec::encoding_length_for_storage(*current) : 0;

    if (equal) {
        batch_state_size_ += kAddressLength + encoding_length_for_storage;
        return;
    }

    auto it{accounts_.find(address)};
    if (it != accounts_.end()) {
        batch_state_size_ -= it->second.has_value() ? state::AccountCodec::encoding_length_for_storage(*it->second) : 0;
        batch_state_size_ += encoding_length_for_storage;
        it->second = current;
    } else {
        batch_state_size_ += kAddressLength + encoding_length_for_storage;
        accounts_[address] = current;
    }

    const bool initial_smart_now_deleted{account_deleted && initial->incarnation};
    const bool initial_smart_now_eoa{!account_deleted && current->incarnation == 0 && initial && initial->incarnation};
    if (initial_smart_now_deleted || initial_smart_now_eoa) {
        if (incarnations_.insert_or_assign(address, initial->incarnation).second) {
            batch_state_size_ += kAddressLength + kIncarnationLength;
        }
    }
}

void Buffer::update_account_code(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& code_hash,
                                 ByteView code) {
    // Don't overwrite existing code so that views of it that were previously returned by read_code are still valid
    const auto [inserted_or_existing_it, inserted] = hash_to_code_.try_emplace(code_hash, code);
    if (inserted) {
        batch_state_size_ += kHashLength + code.length();
    } else {
        batch_state_size_ += code.length() - inserted_or_existing_it->second.length();
    }

    if (storage_prefix_to_code_hash_.insert_or_assign(storage_prefix(address, incarnation), code_hash).second) {
        batch_state_size_ += kPlainStoragePrefixLength + kHashLength;
    }
}

void Buffer::update_storage(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& location,
                            const evmc::bytes32& initial, const evmc::bytes32& current) {
    if (current == initial) {
        return;
    }
    if (block_num_ >= prune_history_threshold_) {
        changed_storage_.insert(address);
        ByteView initial_val{zeroless_view(initial.bytes)};
        block_storage_changes_[block_num_][address][incarnation].insert_or_assign(location, initial_val);
    }

    // Iterator in insert_or_assign return value "is pointing at the element that was inserted or updated"
    // so we cannot use it to determine the old value size: we need to use initial instead
    const auto [_, inserted] = storage_[address][incarnation].insert_or_assign(location, current);
    ByteView current_val{zeroless_view(current.bytes)};
    if (inserted) {
        batch_state_size_ += kPlainStoragePrefixLength + kHashLength + current_val.length();
    } else {
        batch_state_size_ += current_val.length() - zeroless_view(initial.bytes).length();
    }
}

void Buffer::write_history_to_db(bool write_change_sets) {
    size_t written_size{0};
    size_t total_written_size{0};

    bool should_trace{log::test_verbosity(log::Level::kTrace)};
    StopWatch sw;
    sw.start();

    if (!block_account_changes_.empty() && write_change_sets) {
        auto account_change_table{open_cursor(txn_, table::kAccountChangeSet)};
        Bytes change_key(sizeof(BlockNum), '\0');
        Bytes change_value(kAddressLength + 128 /* see comment*/,
                           '\0');  // Max size of encoded value is 85. We allocate - once - some byte more for safety
                                   // and avoid reallocation or resizing in the loop
        for (const auto& [block_num, account_changes] : block_account_changes_) {
            endian::store_big_u64(change_key.data(), block_num);
            written_size += sizeof(BlockNum);
            for (const auto& [address, account_encoded] : account_changes) {
                std::memcpy(&change_value[0], address.bytes, kAddressLength);
                std::memcpy(&change_value[kAddressLength], account_encoded.data(), account_encoded.length());
                mdbx::slice k{to_slice(change_key)};
                mdbx::slice v{change_value.data(), kAddressLength + account_encoded.length()};
                mdbx::error::success_or_throw(account_change_table.put(k, &v, MDBX_APPENDDUP));
                written_size += kAddressLength + account_encoded.length();
            }
        }
        total_written_size += written_size;
        if (should_trace) [[unlikely]] {
            auto [_, duration]{sw.lap()};
            log::Trace("Append Account Changes", {"size", human_size(written_size), "in", StopWatch::format(duration)});
        }
        written_size = 0;
    }
    block_account_changes_.clear();

    if (!block_storage_changes_.empty() && write_change_sets) {
        Bytes change_key(sizeof(BlockNum) + kPlainStoragePrefixLength, '\0');
        Bytes change_value(kHashLength + 128, '\0');  // Se comment above (account changes) for explanation about 128

        auto storage_change_table{open_cursor(txn_, table::kStorageChangeSet)};
        for (const auto& [block_num, storage_changes] : block_storage_changes_) {
            endian::store_big_u64(&change_key[0], block_num);
            written_size += sizeof(BlockNum);
            for (const auto& [address, incarnations_locations_values] : storage_changes) {
                std::memcpy(&change_key[sizeof(BlockNum)], address.bytes, kAddressLength);
                written_size += kAddressLength;
                for (const auto& [incarnation, locations_values] : incarnations_locations_values) {
                    endian::store_big_u64(&change_key[sizeof(BlockNum) + kAddressLength], incarnation);
                    written_size += kIncarnationLength;
                    for (const auto& [location, value] : locations_values) {
                        std::memcpy(&change_value[0], location.bytes, kHashLength);
                        std::memcpy(&change_value[kHashLength], value.data(), value.length());
                        mdbx::slice change_value_slice{change_value.data(), kHashLength + value.length()};
                        mdbx::error::success_or_throw(
                            storage_change_table.put(to_slice(change_key), &change_value_slice, MDBX_APPENDDUP));
                        written_size += kLocationLength + value.length();
                    }
                }
            }
        }
        total_written_size += written_size;
        if (should_trace) [[unlikely]] {
            auto [_, duration]{sw.lap()};
            log::Trace("Append Storage Changes", {"size", human_size(written_size), "in", StopWatch::format(duration)});
        }
        written_size = 0;
    }
    block_storage_changes_.clear();

    if (!receipts_.empty()) {
        auto receipt_table{open_cursor(txn_, table::kBlockReceipts)};
        for (const auto& [block_key, receipts] : receipts_) {
            auto k{to_slice(block_key)};
            auto v{to_slice(receipts)};
            mdbx::error::success_or_throw(receipt_table.put(k, &v, MDBX_APPEND));
            written_size += k.length() + v.length();
        }
        receipts_.clear();
        total_written_size += written_size;
        if (should_trace) [[unlikely]] {
            auto [_, duration]{sw.lap()};
            log::Trace("Append Receipts", {"size", human_size(written_size), "in", StopWatch::format(duration)});
        }
        written_size = 0;
    }

    if (!logs_.empty()) {
        auto log_table{open_cursor(txn_, table::kLogs)};
        for (const auto& [log_key, value] : logs_) {
            auto k{to_slice(log_key)};
            auto v{to_slice(value)};
            mdbx::error::success_or_throw(log_table.put(k, &v, MDBX_APPEND));
            written_size += k.length() + v.length();
        }
        logs_.clear();
        total_written_size += written_size;
        if (should_trace) [[unlikely]] {
            auto [_, duration]{sw.lap()};
            log::Trace("Append Logs", {"size", human_size(written_size), "in", StopWatch::format(duration)});
        }
        written_size = 0;
    }

    if (!call_traces_.empty()) {
        Bytes call_traces_key(sizeof(BlockNum), '\0');
        auto call_traces_cursor{txn_.rw_cursor_dup_sort(table::kCallTraceSet)};
        for (const auto& [block_num, account_and_flags_set] : call_traces_) {
            endian::store_big_u64(call_traces_key.data(), block_num);
            written_size += sizeof(BlockNum);
            for (const auto& account_and_flags : account_and_flags_set) {
                auto account_and_flags_slice{to_slice(account_and_flags)};
                mdbx::error::success_or_throw(
                    call_traces_cursor->put(to_slice(call_traces_key), &account_and_flags_slice, MDBX_APPENDDUP));
                written_size += account_and_flags_slice.size();
            }
        }
        call_traces_.clear();
        total_written_size += written_size;
        if (should_trace) [[unlikely]] {
            auto [_, duration]{sw.lap()};
            log::Trace("Append Call Traces", {"size", human_size(written_size), "in", StopWatch::format(duration)});
        }
    }

    auto [finish_time, _]{sw.stop()};
    if (should_trace) [[unlikely]] {
        log::Trace("Flushed history",
                   {"size", human_size(total_written_size), "in", StopWatch::format(sw.since_start(finish_time))});
    }
}

void Buffer::write_state_to_db() {
    /*
     * ENSURE PlainState updates are Last !!!
     * Also ensure to clear unneeded memory data ASAP to let the OS cache
     * to store more database pages for longer
     */

    size_t written_size{0};
    size_t total_written_size{0};

    bool should_trace{log::test_verbosity(log::Level::kTrace)};
    StopWatch sw;
    sw.start();

    if (!incarnations_.empty()) {
        auto incarnation_table{open_cursor(txn_, table::kIncarnationMap)};
        Bytes data(kIncarnationLength, '\0');
        for (const auto& [address, incarnation] : incarnations_) {
            endian::store_big_u64(&data[0], incarnation);
            incarnation_table.upsert(to_slice(address), to_slice(data));
            written_size += kAddressLength + kIncarnationLength;
        }
        incarnations_.clear();
        total_written_size += written_size;
        if (should_trace) [[unlikely]] {
            auto [_, duration]{sw.lap()};
            log::Trace("Incarnations updated", {"size", human_size(written_size), "in", StopWatch::format(duration)});
        }
        written_size = 0;
    }

    if (!hash_to_code_.empty()) {
        auto code_table{open_cursor(txn_, table::kCode)};
        for (const auto& entry : hash_to_code_) {
            code_table.upsert(to_slice(entry.first), to_slice(entry.second));
            written_size += kHashLength + entry.second.length();
        }
        hash_to_code_.clear();
        total_written_size += written_size;
        if (should_trace) [[unlikely]] {
            auto [_, duration]{sw.lap()};
            log::Trace("Code updated", {"size", human_size(written_size), "in", StopWatch::format(duration)});
        }
        written_size = 0;
    }

    if (!storage_prefix_to_code_hash_.empty()) {
        auto code_hash_table{open_cursor(txn_, table::kPlainCodeHash)};
        for (const auto& entry : storage_prefix_to_code_hash_) {
            code_hash_table.upsert(to_slice(entry.first), to_slice(entry.second));
            written_size += kAddressLength + kIncarnationLength + kHashLength;
        }
        storage_prefix_to_code_hash_.clear();
        total_written_size += written_size;
        if (should_trace) [[unlikely]] {
            auto [_, duration]{sw.lap()};
            log::Trace("Code Hashes updated", {"size", human_size(written_size), "in", StopWatch::format(duration)});
        }
        written_size = 0;
    }

    // Extract sorted index of unique addresses before inserting into the DB
    absl::btree_set<evmc::address> addresses;
    for (auto& x : accounts_) {
        addresses.insert(x.first);
    }
    for (auto& x : storage_) {
        addresses.insert(x.first);
    }

    if (should_trace) [[unlikely]] {
        auto [_, duration]{sw.lap()};
        log::Trace("Sorted addresses", {"in", StopWatch::format(duration)});
    }

    auto state_table = txn_.rw_cursor_dup_sort(table::kPlainState);
    for (const auto& address : addresses) {
        if (auto it{accounts_.find(address)}; it != accounts_.end()) {
            auto key{to_slice(address)};
            state_table->erase(key, /*whole_multivalue=*/true);  // PlainState is multivalue
            if (it->second.has_value()) {
                Bytes encoded = state::AccountCodec::encode_for_storage(*it->second);
                state_table->upsert(key, to_slice(encoded));
                written_size += kAddressLength + encoded.length();
            }
            accounts_.erase(it);
        }

        if (auto it{storage_.find(address)}; it != storage_.end()) {
            for (const auto& [incarnation, contract_storage] : it->second) {
                Bytes prefix{storage_prefix(address, incarnation)};
                // Extract sorted set of storage locations to insert ordered data into the DB
                absl::btree_set<evmc::bytes32> storage_locations;
                for (auto& storage_entry : contract_storage) {
                    storage_locations.insert(storage_entry.first);
                }
                for (const auto& location : storage_locations) {
                    if (auto storage_it{contract_storage.find(location)}; storage_it != contract_storage.end()) {
                        const auto& value{storage_it->second};
                        upsert_storage_value(*state_table, prefix, location.bytes, value.bytes);
                        written_size += prefix.length() + kLocationLength + zeroless_view(value.bytes).size();
                    }
                }
            }
            storage_.erase(it);
        }
    }
    total_written_size += written_size;
    if (should_trace) [[unlikely]] {
        auto [_, duration]{sw.lap()};
        log::Trace("Updated accounts and storage",
                   {"size", human_size(written_size), "in", StopWatch::format(duration)});
    }
    batch_state_size_ = 0;

    auto [time_point, _]{sw.stop()};
    log::Info("Flushed state",
              {"size", human_size(total_written_size), "in", StopWatch::format(sw.since_start(time_point))});
}

void Buffer::write_to_db(bool write_change_sets) {
    write_history_to_db(write_change_sets);

    // This should be very last to be written so updated pages
    // have higher chances not to be evicted from RAM
    write_state_to_db();
}

// Erigon WriteReceipts in core/rawdb/accessors_chain.go
void Buffer::insert_receipts(uint64_t block_num, const std::vector<Receipt>& receipts) {
    for (uint32_t i{0}; i < receipts.size(); ++i) {
        if (receipts[i].logs.empty()) {
            continue;
        }

        Bytes key{log_key(block_num, i)};
        Bytes value{cbor_encode(receipts[i].logs)};

        logs_.insert_or_assign(key, value);
    }

    Bytes key{block_key(block_num)};
    Bytes value{cbor_encode(receipts)};
    receipts_[key] = value;
}

void Buffer::insert_call_traces(BlockNum block_num, const CallTraces& traces) {
    // Collect and sort all unique accounts touched by the call trace (no duplicates)
    absl::btree_set<evmc::address> touched_accounts;
    for (const auto& sender : traces.senders) {
        touched_accounts.insert(sender);
    }
    for (const auto& recipient : traces.recipients) {
        touched_accounts.insert(recipient);
    }

    if (!touched_accounts.empty()) {
        absl::btree_set<Bytes> values;
        for (const auto& account : touched_accounts) {
            Bytes value(kAddressLength + 1, '\0');
            std::memcpy(value.data(), account.bytes, kAddressLength);
            if (traces.senders.contains(account)) {
                value[kAddressLength] |= 1;
            }
            if (traces.recipients.contains(account)) {
                value[kAddressLength] |= 2;
            }
            values.insert(std::move(value));
        }
        call_traces_.emplace(block_num, values);
    }
}

evmc::bytes32 Buffer::state_root_hash() const {
    throw std::runtime_error(std::string(__FUNCTION__).append(" not yet implemented"));
}

uint64_t Buffer::current_canonical_block() const {
    throw std::runtime_error(std::string(__FUNCTION__).append(" not yet implemented"));
}

std::optional<evmc::bytes32> Buffer::canonical_hash(uint64_t) const {
    throw std::runtime_error(std::string(__FUNCTION__).append(" not yet implemented"));
}

void Buffer::canonize_block(uint64_t, const evmc::bytes32&) {
    throw std::runtime_error(std::string(__FUNCTION__).append(" not yet implemented"));
}

void Buffer::decanonize_block(uint64_t) {
    throw std::runtime_error(std::string(__FUNCTION__).append(" not yet implemented"));
}

void Buffer::insert_block(const Block& block, const evmc::bytes32& hash) {
    uint64_t block_num{block.header.number};
    Bytes key{block_key(block_num, hash.bytes)};
    headers_[key] = block.header;
    bodies_[key] = block.copy_body();

    if (block_num == 0) {
        difficulty_[key] = 0;
    } else {
        std::optional<intx::uint256> parent_difficulty{total_difficulty(block_num - 1, block.header.parent_hash)};
        difficulty_[key] = parent_difficulty.value_or(0);
    }
    difficulty_[key] += block.header.difficulty;
}

std::optional<intx::uint256> Buffer::total_difficulty(uint64_t block_num,
                                                      const evmc::bytes32& block_hash) const noexcept {
    Bytes key{block_key(block_num, block_hash.bytes)};
    if (auto it{difficulty_.find(key)}; it != difficulty_.end()) {
        return it->second;
    }
    return db::read_total_difficulty(txn_, key);
}

std::optional<BlockHeader> Buffer::read_header(uint64_t block_num, const evmc::bytes32& block_hash) const noexcept {
    Bytes key{block_key(block_num, block_hash.bytes)};
    if (auto it{headers_.find(key)}; it != headers_.end()) {
        return it->second;
    }
    return data_model_->read_header(block_num, Hash{block_hash.bytes});
}

bool Buffer::read_body(uint64_t block_num, const evmc::bytes32& block_hash, BlockBody& out) const noexcept {
    Bytes key{block_key(block_num, block_hash.bytes)};
    if (auto it{bodies_.find(key)}; it != bodies_.end()) {
        out = it->second;
        return true;
    }
    return data_model_->read_body(block_num, block_hash.bytes, /*read_senders=*/false, out);
}

std::optional<Account> Buffer::read_account(const evmc::address& address) const noexcept {
    if (auto it{accounts_.find(address)}; it != accounts_.end()) {
        return it->second;
    }
    auto db_account{db::read_account(txn_, address, historical_block_)};
    return db_account;
}

ByteView Buffer::read_code(const evmc::address& /*address*/, const evmc::bytes32& code_hash) const noexcept {
    if (auto it{hash_to_code_.find(code_hash)}; it != hash_to_code_.end()) {
        return it->second;
    }
    std::optional<ByteView> code{db::read_code(txn_, code_hash)};
    ByteView empty;
    return code.value_or(empty);
}

evmc::bytes32 Buffer::read_storage(const evmc::address& address, uint64_t incarnation,
                                   const evmc::bytes32& location) const noexcept {
    if (auto it1{storage_.find(address)}; it1 != storage_.end()) {
        if (auto it2{it1->second.find(incarnation)}; it2 != it1->second.end()) {
            if (auto it3{it2->second.find(location)}; it3 != it2->second.end()) {
                return it3->second;
            }
        }
    }
    auto db_storage{db::read_storage(txn_, address, incarnation, location, historical_block_)};
    return db_storage;
}

uint64_t Buffer::previous_incarnation(const evmc::address& address) const noexcept {
    if (auto it{incarnations_.find(address)}; it != incarnations_.end()) {
        return it->second;
    }
    std::optional<uint64_t> incarnation{db::read_previous_incarnation(txn_, address, historical_block_)};
    return incarnation.value_or(0);
}

void Buffer::unwind_state_changes(uint64_t) {
    throw std::runtime_error(std::string(__FUNCTION__).append(" not yet implemented"));
}

}  // namespace silkworm::db
