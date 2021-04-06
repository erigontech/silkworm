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

#include <silkworm/common/log.hpp>
#include <silkworm/db/tables.hpp>

namespace silkworm::trie {

Aggregator::Aggregator(etl::Collector& account_collector) {
    builder_.collector = [&account_collector](ByteView key_hex, const Node& node) {
        etl::Entry e;
        e.key = key_hex;
        e.value = marshal_node(node);
        account_collector.collect(e);
    };
}

void Aggregator::add_account(ByteView key, const Account& a) {
    // TODO[Issue 179] storage
    builder_.add(key, a.rlp(/*storage_root=*/kEmptyRoot));
}

void Aggregator::cut_off() {
    // TODO[Issue 179] implement
}

evmc::bytes32 Aggregator::root() const {
    // TODO[Issue 179] implement
    return {};
}

AccountCursor::AccountCursor(lmdb::Transaction&) {}

bool AccountCursor::can_skip_state() const {
    // TODO[Issue 179] implement
    return false;
}

Bytes AccountCursor::first_uncovered_prefix() const {
    // TODO[Issue 179] implement
    return {};
}

std::optional<Bytes> AccountCursor::key() const {
    // TODO[Issue 179] implement
    return std::nullopt;
}

void AccountCursor::next() {
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

    for (AccountCursor acc_trie{txn_};; acc_trie.next()) {
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
                aggregator_.add_account(key_hex, account);

                // TODO[Issue 179] storage
            }
        }

        // SkipAccounts
        if (!acc_trie.key()) {
            break;
        }

        // TODO[Issue 179] Receive AHashStreamItem
    }

    aggregator_.cut_off();

    return aggregator_.root();
}

Bytes marshal_node(const Node&) {
    // TODO[Issue 179] implement
    return {};
}

Node unmarshal_node(ByteView) {
    Node n;
    // TODO[Issue 179] implement
    return n;
}

void regenerate_db_tries(lmdb::Transaction& txn, const char* tmp_dir, evmc::bytes32* expected_root) {
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
