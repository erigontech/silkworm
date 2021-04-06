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

#include <catch2/catch.hpp>

#include <silkworm/common/temp_dir.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/trie/hash_builder.hpp>
#include <silkworm/types/account.hpp>

namespace silkworm::trie {

TEST_CASE("Layout of account trie") {
    TemporaryDirectory tmp_dir1;
    TemporaryDirectory tmp_dir2;

    lmdb::DatabaseConfig db_config{tmp_dir1.path(), 32 * kMebi};
    db_config.set_readonly(false);
    auto env{lmdb::get_env(db_config)};
    auto txn{env->begin_rw_transaction()};
    db::table::create_all(*txn);

    HashBuilder hb;

    auto hashed_accounts{txn->open(db::table::kHashedAccounts)};

    auto hash1{0xB000000000000000000000000000000000000000000000000000000000000000_bytes32};
    Account a1{0, 3 * kEther};
    hashed_accounts->put(full_view(hash1), a1.encode_for_storage());
    hb.add(full_view(hash1), a1.rlp(/*storage_root=*/kEmptyRoot));

    auto hash2{0xB040000000000000000000000000000000000000000000000000000000000000_bytes32};
    Account a2{0, 1 * kEther};
    hashed_accounts->put(full_view(hash2), a2.encode_for_storage());
    hb.add(full_view(hash2), a2.rlp(/*storage_root=*/kEmptyRoot));

    auto hash3{0xB041000000000000000000000000000000000000000000000000000000000000_bytes32};
    Account a3{0, 2 * kEther};
    hashed_accounts->put(full_view(hash3), a3.encode_for_storage());
    hb.add(full_view(hash3), a3.rlp(/*storage_root=*/kEmptyRoot));

    auto hash4{0xB100000000000000000000000000000000000000000000000000000000000000_bytes32};
    Account a4{0, 4 * kEther};
    hashed_accounts->put(full_view(hash4), a4.encode_for_storage());
    hb.add(full_view(hash4), a4.rlp(/*storage_root=*/kEmptyRoot));

    auto hash5{0xB310000000000000000000000000000000000000000000000000000000000000_bytes32};
    Account a5{0, 8 * kEther};
    hashed_accounts->put(full_view(hash5), a5.encode_for_storage());
    hb.add(full_view(hash5), a5.rlp(/*storage_root=*/kEmptyRoot));

    auto hash6{0xB340000000000000000000000000000000000000000000000000000000000000_bytes32};
    Account a6{0, 1 * kEther};
    hashed_accounts->put(full_view(hash6), a6.encode_for_storage());
    hb.add(full_view(hash6), a6.rlp(/*storage_root=*/kEmptyRoot));

    evmc::bytes32 expected_root{hb.root_hash()};
    regenerate_db_tries(*txn, tmp_dir2.path(), &expected_root);

    auto account_trie{txn->open(db::table::kTrieOfAccounts)};

    auto val1{account_trie->get(*from_hex("0B"))};
    REQUIRE(val1);
    Node node1{unmarshal_node(*val1)};

    CHECK(0b1011 == node1.mask.state);
    CHECK(0b0001 == node1.mask.tree);
    CHECK(0b1001 == node1.mask.hash);

    auto val2{account_trie->get(*from_hex("0B00"))};
    REQUIRE(val2);
    Node node2{unmarshal_node(*val2)};

    CHECK(0b10001 == node2.mask.state);
    CHECK(0b00000 == node2.mask.tree);
    CHECK(0b10000 == node2.mask.hash);

    // TODO[Issue 179] check that there's nothing else in account_trie
}

}  // namespace silkworm::trie
