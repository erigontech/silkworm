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

Aggregator::Aggregator(etl::Collector& account_collector) {
    builder_.collector = [&account_collector](ByteView key_hex, const Node& node) {
        if (key_hex.empty()) {
            return;
        }

        etl::Entry e;
        e.key = key_hex;
        e.value = marshal_node(node);
        account_collector.collect(e);
    };
}

void Aggregator::add_account(ByteView packed_key, const Account& a) {
    // TODO[Issue 179] storage
    builder_.add(packed_key, a.rlp(/*storage_root=*/kEmptyRoot));
}

evmc::bytes32 Aggregator::root() { return builder_.root_hash(); }

AccountTrieCursor::AccountTrieCursor(lmdb::Transaction&) {}

bool AccountTrieCursor::can_skip_state() const {
    // TODO[Issue 179] implement
    return false;
}

Bytes AccountTrieCursor::first_uncovered_prefix() const {
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

DbTrieLoader::DbTrieLoader(lmdb::Transaction& txn, etl::Collector& account_collector)
    : txn_{txn}, aggregator_{account_collector} {}

// CalcTrieRoot algo:
//	for iterateIHOfAccounts {
//		if canSkipState
//          goto SkipAccounts
//
//		for iterateAccounts from prevIH to currentIH {
//			use(account)
//			for iterateIHOfStorage within accountWithIncarnation{
//				if canSkipState
//					goto SkipStorage
//
//				for iterateStorage from prevIHOfStorage to currentIHOfStorage {
//					use(storage)
//				}
//            SkipStorage:
//				use(ihStorage)
//			}
//		}
//    SkipAccounts:
//		use(AccTrie)
//	}
evmc::bytes32 DbTrieLoader::calculate_root() {
    auto acc_state{txn_.open(db::table::kHashedAccounts)};

    for (AccountTrieCursor acc_trie{txn_};; acc_trie.next()) {
        if (!acc_trie.can_skip_state()) {
            for (auto entry{acc_state->seek(acc_trie.first_uncovered_prefix())}; entry; entry = acc_state->get_next()) {
                Bytes key_hex{unpack_nibbles(entry->key)};
                if (acc_trie.key() && acc_trie.key() < key_hex) {
                    break;
                }
                auto [account, err]{decode_account_from_storage(entry->value)};
                if (err != rlp::DecodingResult::kOk) {
                    throw err;
                }
                aggregator_.add_account(entry->key, account);

                // TODO[Issue 179] storage
            }
        }

        // SkipAccounts
        if (!acc_trie.key()) {
            break;
        }

        // TODO[Issue 179] Receive AHashStreamItem
    }

    return aggregator_.root();
}

Bytes marshal_node(const Node& n) {
    size_t buf_size{3 * 2 + n.hashes().size() * kHashLength};
    if (n.root_hash()) {
        buf_size += kHashLength;
    }
    Bytes buf(buf_size, '\0');
    size_t pos{0};

    boost::endian::store_big_u16(&buf[pos], n.state_mask());
    pos += 2;

    boost::endian::store_big_u16(&buf[pos], n.tree_mask());
    pos += 2;

    boost::endian::store_big_u16(&buf[pos], n.hash_mask());
    pos += 2;

    if (n.root_hash()) {
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
    auto state_mask{boost::endian::load_big_u16(v.data())};
    v.remove_prefix(2);
    auto tree_mask{boost::endian::load_big_u16(v.data())};
    v.remove_prefix(2);
    auto hash_mask{boost::endian::load_big_u16(v.data())};
    v.remove_prefix(2);

    std::optional<evmc::bytes32> root_hash{std::nullopt};
    if (std::bitset<16>(hash_mask).count() + 1 == v.length() / kHashLength) {
        root_hash = evmc::bytes32{};
        std::memcpy(root_hash->bytes, v.data(), kHashLength);
        v.remove_prefix(kHashLength);
    }

    size_t num_hashes{v.length() / kHashLength};
    std::vector<evmc::bytes32> hashes(num_hashes);
    for (size_t i{0}; i < num_hashes; ++i) {
        std::memcpy(hashes[i].bytes, v.data(), kHashLength);
        v.remove_prefix(kHashLength);
    }

    return {state_mask, tree_mask, hash_mask, hashes, root_hash};
}

void regenerate_db_tries(lmdb::Transaction& txn, const char* tmp_dir, const evmc::bytes32* expected_root) {
    // TODO[Issue 179] storage
    etl::Collector account_collector{tmp_dir};
    DbTrieLoader loader{txn, account_collector};
    evmc::bytes32 root{loader.calculate_root()};
    if (expected_root && root != *expected_root) {
        SILKWORM_LOG(LogLevel::Error) << "Wrong trie root: " << to_hex(root) << ", expected: " << to_hex(*expected_root)
                                      << "\n";
        throw WrongRoot{};
    }
    auto account_tbl{txn.open(db::table::kTrieOfAccounts)};
    account_collector.load(account_tbl.get());
}

}  // namespace silkworm::trie
