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

#include "access_layer.hpp"

#include <boost/endian/conversion.hpp>
#include <cassert>

#include "history_index.hpp"
#include "tables.hpp"
#include "util.hpp"

namespace silkworm::db {

std::optional<BlockHeader> read_header(lmdb::Transaction& txn, uint64_t block_number, const evmc::bytes32& block_hash) {
    auto table{txn.open(table::kBlockHeaders)};
    Bytes key{block_key(block_number, block_hash.bytes)};
    std::optional<ByteView> header_rlp{table->get(key)};
    if (!header_rlp) {
        return {};
    }

    BlockHeader header;
    rlp::decode(*header_rlp, header);
    return header;
}

std::optional<BlockWithHash> read_block(lmdb::Transaction& txn, uint64_t block_number) {
    auto header_table{txn.open(table::kBlockHeaders)};
    std::optional<ByteView> hash{header_table->get(header_hash_key(block_number))};
    if (!hash) {
        return {};
    }

    BlockWithHash bh{};
    assert(hash->size() == kHashLength);
    std::memcpy(bh.hash.bytes, hash->data(), kHashLength);

    Bytes key{block_key(block_number, bh.hash.bytes)};
    std::optional<ByteView> header_rlp{header_table->get(key)};
    if (!header_rlp) {
        return {};
    }

    rlp::decode(*header_rlp, bh.block.header);

    auto body_table{txn.open(table::kBlockBodies)};
    std::optional<ByteView> body_rlp{body_table->get(key)};
    if (!body_rlp) {
        return {};
    }

    rlp::decode<BlockBody>(*body_rlp, bh.block);
    return bh;
}

std::vector<evmc::address> read_senders(lmdb::Transaction& txn, int64_t block_number, const evmc::bytes32& block_hash) {
    std::vector<evmc::address> senders{};
    auto table{txn.open(table::kSenders)};
    std::optional<ByteView> data{table->get(block_key(block_number, block_hash.bytes))};
    if (!data) {
        return senders;
    }

    assert(data->length() % kAddressLength == 0);
    senders.resize(data->length() / kAddressLength);
    std::memcpy(senders.data(), data->data(), data->size());
    return senders;
}

std::optional<Bytes> read_code(lmdb::Transaction& txn, const evmc::bytes32& code_hash) {
    auto table{txn.open(table::kCode)};
    std::optional<ByteView> val{table->get(full_view(code_hash))};
    if (!val) {
        return {};
    }
    return Bytes{*val};
}

static std::optional<ByteView> find_in_history(lmdb::Transaction& txn, bool storage, ByteView key,
                                               uint64_t block_number) {
    auto history_name{storage ? table::kStorageHistory : table::kAccountHistory};
    auto history_table{txn.open(history_name)};
    std::optional<Entry> entry{history_table->seek(history_index_key(key, block_number))};
    if (!entry) {
        return {};
    }

    ByteView k{entry->key};
    if (storage) {
        if (k.substr(0, kAddressLength) != key.substr(0, kAddressLength) ||
            k.substr(kAddressLength, kHashLength) != key.substr(kStoragePrefixLength)) {
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

    auto change_name{storage ? table::kPlainStorageChangeSet : table::kPlainAccountChangeSet};
    auto change_table{txn.open(change_name)};

    uint64_t change_block{res->change_block};
    std::optional<ByteView> changes{change_table->get(encode_timestamp(change_block))};
    if (!changes) {
        return {};
    }

    if (storage) {
        return StorageChanges::find(*changes, key);
    } else {
        return AccountChanges::find(*changes, key);
    }
}

std::optional<Account> read_account(lmdb::Transaction& txn, const evmc::address& address,
                                    std::optional<uint64_t> block_num) {
    auto key{full_view(address)};

    std::optional<ByteView> encoded{};
    if (block_num) {
        encoded = find_in_history(txn, /*storage=*/false, key, *block_num);
    }
    if (!encoded) {
        auto state_table{txn.open(table::kPlainState)};
        encoded = state_table->get(key);
    }
    if (!encoded || encoded->empty()) {
        return {};
    }

    std::optional<Account> acc{decode_account_from_storage(*encoded)};

    if (acc && acc->incarnation > 0 && acc->code_hash == kEmptyHash) {
        // restore code hash
        auto code_hash_table{txn.open(table::kPlainContractCode)};
        std::optional<ByteView> hash{code_hash_table->get(storage_prefix(address, acc->incarnation))};
        if (hash && hash->length() == kHashLength) {
            std::memcpy(acc->code_hash.bytes, hash->data(), kHashLength);
        }
    }

    return acc;
}

evmc::bytes32 read_storage(lmdb::Transaction& txn, const evmc::address& address, uint64_t incarnation,
                           const evmc::bytes32& key, std::optional<uint64_t> block_num) {
    auto composite_key{storage_key(address, incarnation, key)};
    std::optional<ByteView> val{};
    if (block_num) {
        val = find_in_history(txn, /*storage=*/true, composite_key, *block_num);
    }
    if (!val) {
        auto table{txn.open(table::kPlainState)};
        val = table->get(storage_prefix(address, incarnation), full_view(key));
    }
    if (!val) {
        return {};
    }

    evmc::bytes32 res{};
    std::memcpy(res.bytes + kHashLength - val->length(), val->data(), val->length());
    return res;
}

std::optional<uint64_t> read_previous_incarnation(lmdb::Transaction& txn, const evmc::address& address,
                                                  std::optional<uint64_t> block_num) {
    auto key{full_view(address)};

    if (!block_num) {
        // Current incarnation
        auto incarnation_table{txn.open(table::kIncarnationMap)};
        std::optional<ByteView> val{incarnation_table->get(key)};
        if (!val) {
            return {};
        }
        assert(val->length() == 8);
        return boost::endian::load_big_u64(val->data());
    }

    auto history_table{txn.open(table::kAccountHistory)};
    auto change_table{txn.open(table::kPlainAccountChangeSet)};

    // Search through history and find the latest non-zero incarnation of the account,
    // disregarding future changes (happening after the block_number).
    uint64_t block_number{*block_num};
    while (true) {
        std::optional<Entry> entry{history_table->seek(history_index_key(key, block_number))};
        if (!entry || !has_prefix(entry->key, key)) {
            return {};
        }

        std::optional<history_index::SearchResult> changed_at{history_index::find(entry->value, block_number)};
        if (!changed_at) {
            return {};
        }

        uint64_t change_block{changed_at->change_block};
        std::optional<ByteView> changes{change_table->get(encode_timestamp(change_block))};
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

std::optional<AccountChanges> read_account_changes(lmdb::Transaction& txn, uint64_t block_number) {
    auto table{txn.open(table::kPlainAccountChangeSet)};
    std::optional<ByteView> val{table->get(encode_timestamp(block_number))};
    if (!val) {
        return {};
    }
    return AccountChanges::decode(*val);
}

Bytes read_storage_changes(lmdb::Transaction& txn, uint64_t block_number) {
    auto table{txn.open(table::kPlainStorageChangeSet)};
    std::optional<ByteView> val{table->get(encode_timestamp(block_number))};
    if (!val) {
        return {};
    }
    return Bytes{*val};
}

}  // namespace silkworm::db
