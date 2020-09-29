/*
   Copyright 2020 The Silkworm Authors

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

#include "database.hpp"

#include <cassert>

#include "bucket.hpp"
#include "history_index.hpp"
#include "util.hpp"

namespace silkworm::db {
std::optional<BlockHeader> Database::get_header(uint64_t block_number, const evmc::bytes32& block_hash) {
    auto txn{begin_ro_transaction()};
    auto bucket{txn->get_bucket(bucket::kBlockHeaders)};
    Bytes key{block_key(block_number, block_hash)};
    std::optional<ByteView> header_rlp{bucket->get(key)};
    if (!header_rlp) {
        return {};
    }

    BlockHeader header;
    ByteView view{*header_rlp};
    rlp::decode(view, header);
    return header;
}

std::optional<Account> Database::get_account(const evmc::address& address, uint64_t block_num) {
    auto key{full_view(address)};
    auto txn{begin_ro_transaction()};

    std::optional<ByteView> encoded{find_in_history(*txn, /*storage=*/false, key, block_num)};
    if (!encoded) {
        auto state_bucket{txn->get_bucket(bucket::kPlainState)};
        encoded = state_bucket->get(key);
    }
    if (!encoded || encoded->empty()) {
        return {};
    }

    std::optional<Account> acc{decode_account_from_storage(*encoded)};

    if (acc && acc->incarnation > 0 && acc->code_hash == kEmptyHash) {
        // restore code hash
        auto code_hash_bucket{txn->get_bucket(bucket::kCodeHash)};
        std::optional<ByteView> hash{code_hash_bucket->get(storage_prefix(address, acc->incarnation))};
        if (hash && hash->length() == kHashLength) {
            std::memcpy(acc->code_hash.bytes, hash->data(), kHashLength);
        }
    }

    return acc;
}

std::optional<Bytes> Database::get_code(const evmc::bytes32& code_hash) {
    auto txn{begin_ro_transaction()};
    auto bucket{txn->get_bucket(bucket::kCode)};
    std::optional<ByteView> val{bucket->get(full_view(code_hash))};
    if (!val) {
        return {};
    }
    return Bytes{*val};
}

evmc::bytes32 Database::get_storage(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& key,
                                    uint64_t block_number) {
    auto composite_key{storage_key(address, incarnation, key)};
    auto txn{begin_ro_transaction()};
    std::optional<ByteView> val{find_in_history(*txn, /*storage=*/true, composite_key, block_number)};
    if (!val) {
        auto bucket{txn->get_bucket(bucket::kPlainState)};
        val = bucket->get(composite_key);
    }
    if (!val) {
        return {};
    }

    evmc::bytes32 res{};
    std::memcpy(res.bytes + kHashLength - val->length(), val->data(), val->length());
    return res;
}

std::optional<uint64_t> Database::previous_incarnation(const evmc::address& address, uint64_t block_number) {
    auto key{full_view(address)};
    auto txn{begin_ro_transaction()};
    auto history_bucket{txn->get_bucket(bucket::kAccountHistory)};
    auto change_bucket{txn->get_bucket(bucket::kAccountChanges)};
    auto cursor{history_bucket->cursor()};

    while (true) {
        std::optional<Entry> entry{cursor->seek(history_index_key(key, block_number))};
        if (!entry || !has_prefix(entry->key, key)) {
            return {};
        }

        std::optional<history_index::SearchResult> changed_at{history_index::find(entry->value, block_number)};
        if (!changed_at) {
            return {};
        }

        uint64_t change_block{changed_at->change_block};
        std::optional<ByteView> changes{change_bucket->get(encode_timestamp(change_block))};
        if (!changes) {
            return {};
        }

        std::optional<ByteView> encoded{AccountChanges::find(*changes, key)};
        if (encoded && !encoded->empty()) {
            std::optional<Account> acc{decode_account_from_storage(*encoded)};
            if (acc && acc->incarnation > 0) {
                return acc->incarnation;
            }
        }

        // The account was deleted or had zero incarnation,
        // so go further back in time.
        changed_at = history_index::find_previous(entry->value, block_number);
        if (!changed_at) {
            return {};
        }
        block_number = changed_at->change_block;
    }
}

std::optional<ByteView> Database::find_in_history(Transaction& txn, bool storage, ByteView key, uint64_t block_number) {
    auto history_name{storage ? bucket::kStorageHistory : bucket::kAccountHistory};
    auto history_bucket{txn.get_bucket(history_name)};
    auto cursor{history_bucket->cursor()};
    std::optional<Entry> entry{cursor->seek(history_index_key(key, block_number))};
    if (!entry) {
        return {};
    }

    ByteView k{entry->key};
    if (storage) {
        if (k.substr(0, kAddressLength) != key.substr(0, kAddressLength) ||
            k.substr(kAddressLength, kHashLength) != key.substr(kAddressLength + kIncarnationLength)) {
            return {};
        }
    } else if (!has_prefix(k, key)) {
        return {};
    }

    std::optional<history_index::SearchResult> res{history_index::find(entry->value, block_number)};
    if (!res) {
        return {};
    }

    if (res->new_record && !storage) {
        return ByteView{};
    }

    auto change_name{storage ? bucket::kStorageChanges : bucket::kAccountChanges};
    auto change_bucket{txn.get_bucket(change_name)};

    uint64_t change_block{res->change_block};
    std::optional<ByteView> changes{change_bucket->get(encode_timestamp(change_block))};
    if (!changes) {
        return {};
    }

    if (storage) {
        return StorageChanges::find(*changes, key);
    } else {
        return AccountChanges::find(*changes, key);
    }
}
}  // namespace silkworm::db
