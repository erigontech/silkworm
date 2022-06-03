/*
   Copyright 2020-2022 The Silkworm Authors

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
#include <iostream>

#include <absl/container/btree_set.h>

#include <silkworm/common/endian.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/common/stopwatch.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/types/log_cbor.hpp>
#include <silkworm/types/receipt_cbor.hpp>

namespace silkworm::db {

void Buffer::begin_block(uint64_t block_number) {
    block_number_ = block_number;
    changed_storage_.clear();
}

void Buffer::update_account(const evmc::address& address, std::optional<Account> initial,
                            std::optional<Account> current) {
    const bool equal{current == initial};
    const bool account_deleted{!current.has_value()};

    if (equal && !account_deleted && !changed_storage_.contains(address)) {
        // Follows the Erigon logic when to populate account changes.
        // See (ChangeSetWriter)UpdateAccountData & DeleteAccount.
        return;
    }

    if (block_number_ >= prune_history_threshold_) {
        Bytes encoded_initial{};
        if (initial) {
            bool omit_code_hash{!account_deleted};
            encoded_initial = initial->encode_for_storage(omit_code_hash);
        }

        size_t payload_size{block_account_changes_.contains(block_number_) ? 0 : sizeof(BlockNum)};
        if (block_account_changes_[block_number_].insert_or_assign(address, encoded_initial).second) {
            payload_size += kAddressLength + encoded_initial.length();
        }
        batch_history_size_ += payload_size;
    }

    if (equal) {
        return;
    }
    auto it{accounts_.find(address)};
    if (it != accounts_.end()) {
        batch_state_size_ -= it->second.has_value() ? sizeof(Account) : 0;
        batch_state_size_ += (current ? sizeof(Account) : 0);
        it->second = current;
    } else {
        batch_state_size_ += kAddressLength + (current ? sizeof(Account) : 0);
        accounts_[address] = current;
    }

    if (account_deleted && initial->incarnation) {
        if (incarnations_.insert_or_assign(address, initial->incarnation).second) {
            batch_state_size_ += kAddressLength + kIncarnationLength;
        }
    }
}

void Buffer::update_account_code(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& code_hash,
                                 ByteView code) {
    // Don't overwrite already existing code so that views of it
    // that were previously returned by read_code() are still valid.
    if (hash_to_code_.try_emplace(code_hash, code).second) {
        batch_state_size_ += kHashLength + code.length();
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
    if (block_number_ >= prune_history_threshold_) {
        changed_storage_.insert(address);
        ByteView initial_val{zeroless_view(initial)};
        if (block_storage_changes_[block_number_][address][incarnation]
                .insert_or_assign(location, initial_val)
                .second) {
            batch_history_size_ += kPlainStoragePrefixLength + kHashLength + initial_val.size();
        }
    }

    if (storage_[address][incarnation].insert_or_assign(location, current).second) {
        batch_state_size_ += kPlainStoragePrefixLength + kHashLength + kHashLength;
    }
}

void Buffer::write_history_to_db() {
    size_t written_size{0};
    size_t total_written_size{0};

    bool should_trace{log::test_verbosity(log::Level::kTrace)};
    StopWatch sw;
    sw.start();

    if (!block_account_changes_.empty()) {
        auto account_change_table{db::open_cursor(txn_, table::kAccountChangeSet)};
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
        block_account_changes_.clear();
        total_written_size += written_size;
        if (should_trace) {
            auto [_, duration]{sw.lap()};
            log::Trace("Append Account Changes", {"size", human_size(written_size), "in", StopWatch::format(duration)});
        }
        written_size = 0;
    }

    if (!block_storage_changes_.empty()) {
        Bytes change_key(sizeof(BlockNum) + kPlainStoragePrefixLength, '\0');
        Bytes change_value(kHashLength + 128, '\0');  // Se comment above (account changes) for explanation about 128

        auto storage_change_table{db::open_cursor(txn_, table::kStorageChangeSet)};
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
        block_storage_changes_.clear();
        total_written_size += written_size;
        if (should_trace) {
            auto [_, duration]{sw.lap()};
            log::Trace("Append Storage Changes", {"size", human_size(written_size), "in", StopWatch::format(duration)});
        }
        written_size = 0;
    }

    if (!receipts_.empty()) {
        auto receipt_table{db::open_cursor(txn_, table::kBlockReceipts)};
        for (const auto& [block_key, receipts] : receipts_) {
            auto k{to_slice(block_key)};
            auto v{to_slice(receipts)};
            mdbx::error::success_or_throw(receipt_table.put(k, &v, MDBX_APPEND));
            written_size += k.length() + v.length();
        }
        receipts_.clear();
        total_written_size += written_size;
        if (should_trace) {
            auto [_, duration]{sw.lap()};
            log::Trace("Append Receipts", {"size", human_size(written_size), "in", StopWatch::format(duration)});
        }
        written_size = 0;
    }

    if (!logs_.empty()) {
        auto log_table{db::open_cursor(txn_, table::kLogs)};
        for (const auto& [log_key, value] : logs_) {
            auto k{to_slice(log_key)};
            auto v{to_slice(value)};
            mdbx::error::success_or_throw(log_table.put(k, &v, MDBX_APPEND));
            written_size += k.length() + v.length();
        }
        logs_.clear();
        total_written_size += written_size;
        if (should_trace) {
            auto [_, duration]{sw.lap()};
            log::Trace("Append Logs", {"size", human_size(written_size), "in", StopWatch::format(duration)});
        }
        written_size = 0;
    }

    batch_history_size_ = 0;
    auto [finish_time, _]{sw.stop()};
    log::Info("Flushed history",
              {"size", human_size(total_written_size), "in", StopWatch::format(sw.since_start(finish_time))});
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
        auto incarnation_table{db::open_cursor(txn_, table::kIncarnationMap)};
        Bytes data(kIncarnationLength, '\0');
        for (const auto& [address, incarnation] : incarnations_) {
            endian::store_big_u64(&data[0], incarnation);
            incarnation_table.upsert(to_slice(address), to_slice(data));
            written_size += kAddressLength + kIncarnationLength;
        }
        incarnations_.clear();
        total_written_size += written_size;
        if (should_trace) {
            auto [_, duration]{sw.lap()};
            log::Trace("Incarnations updated", {"size", human_size(written_size), "in", StopWatch::format(duration)});
        }
        written_size = 0;
    }

    if (!hash_to_code_.empty()) {
        auto code_table{db::open_cursor(txn_, table::kCode)};
        for (const auto& entry : hash_to_code_) {
            code_table.upsert(to_slice(entry.first), to_slice(entry.second));
            written_size += kHashLength + entry.second.length();
        }
        hash_to_code_.clear();
        total_written_size += written_size;
        if (should_trace) {
            auto [_, duration]{sw.lap()};
            log::Trace("Code updated", {"size", human_size(written_size), "in", StopWatch::format(duration)});
        }
        written_size = 0;
    }

    if (!storage_prefix_to_code_hash_.empty()) {
        auto code_hash_table{db::open_cursor(txn_, table::kPlainCodeHash)};
        for (const auto& entry : storage_prefix_to_code_hash_) {
            code_hash_table.upsert(to_slice(entry.first), to_slice(entry.second));
            written_size += kAddressLength + kIncarnationLength + kHashLength;
        }
        storage_prefix_to_code_hash_.clear();
        total_written_size += written_size;
        if (should_trace) {
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

    if (should_trace) {
        auto [_, duration]{sw.lap()};
        log::Trace("Sorted addresses", {"in", StopWatch::format(duration)});
    }

    auto state_table{db::open_cursor(txn_, table::kPlainState)};
    for (const auto& address : addresses) {
        if (auto it{accounts_.find(address)}; it != accounts_.end()) {
            auto key{to_slice(address)};
            state_table.erase(key, /*whole_multivalue=*/true);  // PlainState is multivalue
            if (it->second.has_value()) {
                Bytes encoded{it->second->encode_for_storage()};
                state_table.upsert(key, to_slice(encoded));
                written_size += kAddressLength + encoded.length();
            }
            accounts_.erase(it);
        }

        if (auto it{storage_.find(address)}; it != storage_.end()) {
            for (const auto& [incarnation, contract_storage] : it->second) {
                Bytes prefix{storage_prefix(address, incarnation)};
                for (const auto& [location, value] : contract_storage) {
                    upsert_storage_value(state_table, prefix, location, value);
                    written_size += prefix.length() + kLocationLength + kHashLength;
                }
            }
            storage_.erase(it);
        }
    }
    total_written_size += written_size;
    if (should_trace) {
        auto [_, duration]{sw.lap()};
        log::Trace("Updated accounts and storage",
                   {"size", human_size(written_size), "in", StopWatch::format(duration)});
    }
    written_size = 0;
    batch_state_size_ = 0;

    auto [time_point, _]{sw.stop()};
    log::Info("Flushed state",
              {"size", human_size(total_written_size), "in", StopWatch::format(sw.since_start(time_point))});
}

void Buffer::write_to_db() {
    write_history_to_db();

    // This should be very last to be written so updated pages
    // have higher chances not to be evicted from RAM
    write_state_to_db();
}

// Erigon WriteReceipts in core/rawdb/accessors_chain.go
void Buffer::insert_receipts(uint64_t block_number, const std::vector<Receipt>& receipts) {
    for (uint32_t i{0}; i < receipts.size(); ++i) {
        if (receipts[i].logs.empty()) {
            continue;
        }

        Bytes key{log_key(block_number, i)};
        Bytes value{cbor_encode(receipts[i].logs)};

        if (logs_.insert_or_assign(key, value).second) {
            batch_history_size_ += key.size() + value.size();
        }
    }

    Bytes key{block_key(block_number)};
    Bytes value{cbor_encode(receipts)};
    receipts_[key] = value;
    batch_history_size_ += key.size() + value.size();
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
    uint64_t block_number{block.header.number};
    Bytes key{block_key(block_number, hash.bytes)};
    headers_[key] = block.header;
    bodies_[key] = block;

    if (block_number == 0) {
        difficulty_[key] = 0;
    } else {
        std::optional<intx::uint256> parent_difficulty{total_difficulty(block_number - 1, block.header.parent_hash)};
        difficulty_[key] = parent_difficulty.value_or(0);
    }
    difficulty_[key] += block.header.difficulty;
}

std::optional<intx::uint256> Buffer::total_difficulty(uint64_t block_number,
                                                      const evmc::bytes32& block_hash) const noexcept {
    Bytes key{block_key(block_number, block_hash.bytes)};
    if (auto it{difficulty_.find(key)}; it != difficulty_.end()) {
        return it->second;
    }
    return db::read_total_difficulty(txn_, key);
}

std::optional<BlockHeader> Buffer::read_header(uint64_t block_number, const evmc::bytes32& block_hash) const noexcept {
    Bytes key{block_key(block_number, block_hash.bytes)};
    if (auto it{headers_.find(key)}; it != headers_.end()) {
        return it->second;
    }
    return db::read_header(txn_, key);
}

bool Buffer::read_body(uint64_t block_number, const evmc::bytes32& block_hash, BlockBody& body) const noexcept {
    Bytes key{block_key(block_number, block_hash.bytes)};
    if (auto it{bodies_.find(key)}; it != bodies_.end()) {
        body = it->second;
        return true;
    }
    return db::read_body(txn_, key, /*read_senders=*/false, body);
}

std::optional<Account> Buffer::read_account(const evmc::address& address) const noexcept {
    if (auto it{accounts_.find(address)}; it != accounts_.end()) {
        return it->second;
    }
    auto db_account{db::read_account(txn_, address, historical_block_)};
    accounts_[address] = db_account;
    batch_state_size_ += kAddressLength + db_account.value_or(Account()).encoding_length_for_storage();
    return db_account;
}

ByteView Buffer::read_code(const evmc::bytes32& code_hash) const noexcept {
    if (auto it{hash_to_code_.find(code_hash)}; it != hash_to_code_.end()) {
        return it->second;
    }
    std::optional<ByteView> code{db::read_code(txn_, code_hash)};
    if (code.has_value()) {
        return *code;
    } else {
        return {};
    }
}

evmc::bytes32 Buffer::read_storage(const evmc::address& address, uint64_t incarnation,
                                   const evmc::bytes32& location) const noexcept {
    size_t payload_length{kAddressLength + kIncarnationLength + kLocationLength + kHashLength};
    if (auto it1{storage_.find(address)}; it1 != storage_.end()) {
        payload_length -= kAddressLength;
        if (auto it2{it1->second.find(incarnation)}; it2 != it1->second.end()) {
            payload_length -= kIncarnationLength;
            if (auto it3{it2->second.find(location)}; it3 != it2->second.end()) {
                return it3->second;
            }
        }
    }
    auto db_storage{db::read_storage(txn_, address, incarnation, location, historical_block_)};
    storage_[address][incarnation][location] = db_storage;
    batch_state_size_ += payload_length;
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
