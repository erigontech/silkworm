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

void Aggregator::cut_off() {
    // TODO[Issue 179] implement
}

evmc::bytes32 Aggregator::root() const {
    // TODO[Issue 179] implement
    return {};
}

AccountTrieCursor::AccountTrieCursor(lmdb::Transaction&, etl::Collector&) {}

bool AccountTrieCursor::can_skip_state() const {
    // TODO[Issue 179] implement
    return false;
}

void AccountTrieCursor::next() {
    // TODO[Issue 179] implement
}

DbTrieLoader::DbTrieLoader(lmdb::Transaction& txn, etl::Collector& account_collector)
    : txn_{txn}, account_collector_{account_collector} {}

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
    auto account_state_cursor{txn_.open(db::table::kHashedAccounts)};

    for (AccountTrieCursor account_trie_cursor{txn_, account_collector_};; account_trie_cursor.next()) {
        // TODO[Issue 179] can_skip_state

        // TODO[Issue 179] implement inner loop
        break;
    }

    aggregator_.cut_off();

    return aggregator_.root();
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
        SILKWORM_LOG(LogError) << "Wrong trie root: " << to_hex(root) << ", expected: " << to_hex(*expected_root)
                               << "\n";
        throw WrongRoot{};
    }
    auto account_tbl{txn.open(db::table::kTrieOfAccounts)};
    account_collector.load(account_tbl.get());
}

}  // namespace silkworm::trie
