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

#include "db_trie.hpp"

#include <bitset>

#include <boost/endian/conversion.hpp>

#include <silkworm/common/log.hpp>
#include <silkworm/db/tables.hpp>

namespace silkworm::trie {

AccountTrieCursor::AccountTrieCursor(lmdb::Transaction&) {}

Bytes AccountTrieCursor::first_uncovered_prefix() {
    // TODO[Issue 179] implement
    return {};
}

std::optional<Bytes> AccountTrieCursor::key() const {
    // TODO[Issue 179] implement
    return std::nullopt;
}

void AccountTrieCursor::next() {
    // TODO[Issue 179] implement
}

bool AccountTrieCursor::can_skip_state() const {
    // TODO[Issue 179] implement
    return false;
}

StorageTrieCursor::StorageTrieCursor(lmdb::Transaction&) {}

Bytes StorageTrieCursor::seek_to_account(ByteView) {
    // TODO[Issue 179] implement
    return {};
}

Bytes StorageTrieCursor::first_uncovered_prefix() {
    // TODO[Issue 179] implement
    return Bytes(1, '\0');
}

std::optional<Bytes> StorageTrieCursor::key() const {
    // TODO[Issue 179] implement
    return std::nullopt;
}

void StorageTrieCursor::next() {
    // TODO[Issue 179] implement
}

bool StorageTrieCursor::can_skip_state() const {
    // TODO[Issue 179] implement
    return false;
}

DbTrieLoader::DbTrieLoader(lmdb::Transaction& txn, etl::Collector& account_collector, etl::Collector& storage_collector)
    : txn_{txn}, storage_collector_{storage_collector} {
    hb_.node_collector = [&account_collector](ByteView unpacked_key, const Node& node) {
        if (unpacked_key.empty()) {
            return;
        }

        etl::Entry e;
        e.key = unpacked_key;
        e.value = marshal_node(node);
        account_collector.collect(e);
    };
}

// calculate_root algo:
//  for iterateIHOfAccounts {
//      if canSkipState
//          goto use_account_trie
//
//      for iterateAccounts from prevIH to currentIH {
//          use(account)
//          for iterateIHOfStorage within accountWithIncarnation{
//              if canSkipState
//                  goto use_storage_trie
//
//              for iterateStorage from prevIHOfStorage to currentIHOfStorage {
//                  use(storage)
//              }
//            use_storage_trie:
//              use(ihStorage)
//          }
//      }
//    use_account_trie:
//      use(AccTrie)
//  }
evmc::bytes32 DbTrieLoader::calculate_root() {
    auto acc_state{txn_.open(db::table::kHashedAccounts)};
    auto storage_state{txn_.open(db::table::kHashedStorage)};

    StorageTrieCursor storage_trie{txn_};

    for (AccountTrieCursor acc_trie{txn_};; acc_trie.next()) {
        if (acc_trie.can_skip_state()) {
            goto use_account_trie;
        }

        for (auto a{acc_state->seek(acc_trie.first_uncovered_prefix())}; a.has_value(); a = acc_state->get_next()) {
            const Bytes unpacked_key{unpack_nibbles(a->key)};
            if (acc_trie.key().has_value() && acc_trie.key().value() < unpacked_key) {
                break;
            }
            const auto [account, err]{decode_account_from_storage(a->value)};
            if (err != rlp::DecodingResult::kOk) {
                throw err;
            }

            evmc::bytes32 storage_root{kEmptyRoot};

            if (account.incarnation) {
                const Bytes acc_with_inc{db::storage_prefix(a->key, account.incarnation)};

                HashBuilder storage_hb;
                storage_hb.node_collector = [&](ByteView unpacked_key, const Node& node) {
                    etl::Entry e{acc_with_inc, marshal_node(node)};
                    e.key.append(unpacked_key);
                    storage_collector_.collect(e);
                };

                for (storage_trie.seek_to_account(acc_with_inc);; storage_trie.next()) {
                    if (storage_trie.can_skip_state()) {
                        goto use_storage_trie;
                    }

                    for (auto s{storage_state->seek_dup(acc_with_inc, storage_trie.first_uncovered_prefix())};
                         s.has_value(); s = storage_state->get_next_dup()) {
                        const ByteView packed_loc{s->substr(0, kHashLength)};
                        const ByteView value{s->substr(kHashLength)};
                        const Bytes unpacked_loc{unpack_nibbles(packed_loc)};
                        if (storage_trie.key().has_value() && storage_trie.key().value() < unpacked_loc) {
                            break;
                        }

                        rlp_.clear();
                        rlp::encode(rlp_, value);
                        storage_hb.add(packed_loc, rlp_);
                    }

                use_storage_trie:
                    if (!storage_trie.key().has_value()) {
                        break;
                    }

                    // TODO[Issue 179] use storage trie
                }

                storage_root = storage_hb.root_hash();
            }

            hb_.add(a->key, account.rlp(storage_root));
        }

    use_account_trie:
        if (!acc_trie.key().has_value()) {
            break;
        }

        // TODO[Issue 179] use account trie
    }

    return hb_.root_hash();
}

Bytes marshal_node(const Node& n) {

    size_t buf_size{/* 3 masks state/tree/hash 2 bytes each */ 6 +
                    /* root hash */ (n.root_hash().has_value() ? kHashLength : 0u) +
                    /* hashes */ n.hashes().size() * kHashLength};

    Bytes buf(buf_size, '\0');
    size_t pos{0};

    boost::endian::store_big_u16(&buf[pos], n.state_mask());
    pos += 2;

    boost::endian::store_big_u16(&buf[pos], n.tree_mask());
    pos += 2;

    boost::endian::store_big_u16(&buf[pos], n.hash_mask());
    pos += 2;

    if (n.root_hash().has_value()) {
        std::memcpy(&buf[pos], n.root_hash()->bytes, kHashLength);
        pos += kHashLength;
    }

    for (const auto& hash : n.hashes()) {
        std::memcpy(&buf[pos], hash.bytes, kHashLength);
        pos += kHashLength;
    }

    return buf;
}

Node unmarshal_node(ByteView v) {

    if (v.length() < 6) {
        // At least state/tree/hash masks need to be present
        throw std::invalid_argument("unmarshal_node : input too short");
    }

    const auto state_mask{boost::endian::load_big_u16(v.data())};
    v.remove_prefix(2);
    const auto tree_mask{boost::endian::load_big_u16(v.data())};
    v.remove_prefix(2);
    const auto hash_mask{boost::endian::load_big_u16(v.data())};
    v.remove_prefix(2);

    std::optional<evmc::bytes32> root_hash{std::nullopt};
    if (std::bitset<16>(hash_mask).count() + 1 == v.length() / kHashLength) {
        root_hash = evmc::bytes32{};
        std::memcpy(root_hash->bytes, v.data(), kHashLength);
        v.remove_prefix(kHashLength);
    }

    const size_t num_hashes{v.length() / kHashLength};
    std::vector<evmc::bytes32> hashes(num_hashes);
    for (size_t i{0}; i < num_hashes; ++i) {
        std::memcpy(hashes[i].bytes, v.data(), kHashLength);
        v.remove_prefix(kHashLength);
    }

    return {state_mask, tree_mask, hash_mask, hashes, root_hash};
}

evmc::bytes32 regenerate_db_tries(lmdb::Transaction& txn, const char* tmp_dir, const evmc::bytes32* expected_root) {
    etl::Collector account_collector{tmp_dir};
    etl::Collector storage_collector{tmp_dir};
    DbTrieLoader loader{txn, account_collector, storage_collector};
    const evmc::bytes32 root{loader.calculate_root()};
    if (expected_root && root != *expected_root) {
        SILKWORM_LOG(LogLevel::Error) << "Wrong trie root: " << to_hex(root) << ", expected: " << to_hex(*expected_root)
                                      << "\n";
        throw WrongRoot{};
    }
    auto account_tbl{txn.open(db::table::kTrieOfAccounts)};
    account_collector.load(account_tbl.get());
    auto storage_tbl{txn.open(db::table::kTrieOfStorage)};
    storage_collector.load(storage_tbl.get());
    return root;
}

}  // namespace silkworm::trie
