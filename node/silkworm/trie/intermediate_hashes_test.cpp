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

#include "intermediate_hashes.hpp"

#include <catch2/catch.hpp>

#include <silkworm/common/endian.hpp>
#include <silkworm/common/test_context.hpp>
#include <silkworm/common/util.hpp>
#include <silkworm/db/tables.hpp>

namespace silkworm::trie {

static Bytes nibbles_from_hex(std::string_view s) {
    Bytes unpacked(s.size(), '\0');
    for (size_t i{0}; i < s.size(); ++i) {
        unpacked[i] = *decode_hex_digit(s[i]);
    }
    return unpacked;
}

static std::string nibbles_to_hex(ByteView unpacked) {
    static const char* kHexDigits{"0123456789ABCDEF"};

    std::string out;
    out.reserve(unpacked.length());

    for (uint8_t x : unpacked) {
        out.push_back(kHexDigits[x]);
    }

    return out;
}

TEST_CASE("Cursor traversal 1") {
    test::Context context;
    auto& txn{context.txn()};

    auto trie{db::open_cursor(txn, db::table::kTrieOfAccounts)};

    const Bytes key1{nibbles_from_hex("1")};
    const Node node1{/*state_mask=*/0b1011, /*tree_mask=*/0b1001, /*hash_mask=*/0, /*hashes=*/{}};
    trie.upsert(db::to_slice(key1), db::to_slice(marshal_node(node1)));

    const Bytes key2{nibbles_from_hex("10B")};
    const Node node2{/*state_mask=*/0b1010, /*tree_mask=*/0, /*hash_mask=*/0, /*hashes=*/{}};
    trie.upsert(db::to_slice(key2), db::to_slice(marshal_node(node2)));

    const Bytes key3{nibbles_from_hex("13")};
    const Node node3{/*state_mask=*/0b1110, /*tree_mask=*/0, /*hash_mask=*/0, /*hashes=*/{}};
    trie.upsert(db::to_slice(key3), db::to_slice(marshal_node(node3)));

    PrefixSet changed;
    Cursor cursor{trie, changed};

    // Traversal should be in pre-order:
    // 1. Visit the current node
    // 2. Recursively traverse the current node's left subtree.
    // 3. Recursively traverse the current node's right subtree.
    // https://en.wikipedia.org/wiki/Tree_traversal#Pre-order,_NLR

    // Only nibbles with state flag should be traversed.

    CHECK((cursor.key() != std::nullopt && cursor.key()->empty()));  // root

    cursor.next();
    CHECK(nibbles_to_hex(*cursor.key()) == "10");
    cursor.next();
    CHECK(nibbles_to_hex(*cursor.key()) == "10B1");
    cursor.next();
    CHECK(nibbles_to_hex(*cursor.key()) == "10B3");
    cursor.next();
    CHECK(nibbles_to_hex(*cursor.key()) == "11");
    cursor.next();
    CHECK(nibbles_to_hex(*cursor.key()) == "13");
    cursor.next();
    CHECK(nibbles_to_hex(*cursor.key()) == "131");
    cursor.next();
    CHECK(nibbles_to_hex(*cursor.key()) == "132");
    cursor.next();
    CHECK(nibbles_to_hex(*cursor.key()) == "133");

    cursor.next();
    CHECK(cursor.key() == std::nullopt);  // end of trie
}

TEST_CASE("Cursor traversal 2") {
    test::Context context;
    auto& txn{context.txn()};

    auto trie{db::open_cursor(txn, db::table::kTrieOfAccounts)};

    const Bytes key1{nibbles_from_hex("4")};
    const Node node1{/*state_mask=*/0b10100, /*tree_mask=*/0, /*hash_mask=*/0b00100,
                     /*hashes=*/{0x0384e6e2c2b33c4eb911a08a7ff57f83dc3eb86d8d0c92ec112f3b416d6685a9_bytes32}};
    trie.upsert(db::to_slice(key1), db::to_slice(marshal_node(node1)));

    const Bytes key2{nibbles_from_hex("6")};
    const Node node2{/*state_mask=*/0b10010, /*tree_mask=*/0, /*hash_mask=*/0b00010,
                     /*hashes=*/{0x7f9a58b00625a6e725559acf327baf88d90e4a5b65a2003acd24f110c0441df1_bytes32}};
    trie.upsert(db::to_slice(key2), db::to_slice(marshal_node(node2)));

    PrefixSet changed;
    Cursor cursor{trie, changed};

    CHECK((cursor.key() != std::nullopt && cursor.key()->empty()));  // root

    cursor.next();
    CHECK(nibbles_to_hex(*cursor.key()) == "42");
    cursor.next();
    CHECK(nibbles_to_hex(*cursor.key()) == "44");
    cursor.next();
    CHECK(nibbles_to_hex(*cursor.key()) == "61");
    cursor.next();
    CHECK(nibbles_to_hex(*cursor.key()) == "64");

    cursor.next();
    CHECK(cursor.key() == std::nullopt);  // end of trie
}

TEST_CASE("Cursor traversal within prefix") {
    test::Context context;
    auto& txn{context.txn()};

    auto trie{db::open_cursor(txn, db::table::kTrieOfStorage)};

    static const Bytes prefix_a{*from_hex("aa02")};
    static const Bytes prefix_b{*from_hex("bb05")};
    static const Bytes prefix_c{*from_hex("cc01")};

    static const Node node_a{/*state_mask=*/0b10100, /*tree_mask=*/0, /*hash_mask=*/0, /*hashes=*/{},
                             /*root_hash=*/0x2e1b81393448317fc1834241119c23f9e1763f7a662f8078949accc35b0d3b13_bytes32};
    trie.upsert(db::to_slice(prefix_a), db::to_slice(marshal_node(node_a)));

    static const Node node_b1{/*state_mask=*/0b10100, /*tree_mask=*/0b00100, /*hash_mask=*/0, /*hashes=*/{},
                              /*root_hash=*/0xc570b66136e99d07c6c6360769de1d9397805849879dd7c79cf0b8e6694bfb0e_bytes32};
    static const Node node_b2{/*state_mask=*/0b00010, /*tree_mask=*/0, /*hash_mask=*/0b00010,
                              /*hashes=*/{0x6fc81f58df057a25ca6b687a6db54aaa12fbea1baf03aa3db44d499fb8a7af65_bytes32},
                              /*root_hash=*/std::nullopt};
    trie.upsert(db::to_slice(prefix_b), db::to_slice(marshal_node(node_b1)));
    trie.upsert(db::to_slice(prefix_b + nibbles_from_hex("2")), db::to_slice(marshal_node(node_b2)));

    static const Node node_c{/*state_mask=*/0b11110, /*tree_mask=*/0, /*hash_mask=*/0, /*hashes=*/{},
                             /*root_hash=*/0x0f12bed8e3cc4cce692d234e69a4d79c0e74ab05ecb808dad588212eab788c31_bytes32};
    trie.upsert(db::to_slice(prefix_c), db::to_slice(marshal_node(node_c)));

    SECTION("No changes") {
        PrefixSet changed;
        Cursor cursor{trie, changed, prefix_b};

        CHECK((cursor.key() != std::nullopt && cursor.key()->empty()));  // root
        CHECK(cursor.can_skip_state());                                  // due to root_hash
        cursor.next();                                                   // skips to end of trie
        CHECK(cursor.key() == std::nullopt);
    }

    SECTION("Some  changes") {
        PrefixSet changed;
        changed.insert(prefix_b + nibbles_from_hex("D5"));
        changed.insert(prefix_c + nibbles_from_hex("B8"));
        Cursor cursor{trie, changed, prefix_b};

        CHECK((cursor.key() != std::nullopt && cursor.key()->empty()));  // root
        CHECK(!cursor.can_skip_state());
        cursor.next();
        CHECK(nibbles_to_hex(*cursor.key()) == "2");
        cursor.next();
        CHECK(nibbles_to_hex(*cursor.key()) == "21");
        cursor.next();
        CHECK(nibbles_to_hex(*cursor.key()) == "4");

        cursor.next();
        CHECK(cursor.key() == std::nullopt);  // end of trie
    }
}

static evmc::bytes32 setup_storage(mdbx::txn& txn, ByteView storage_key) {
    const auto loc1{0x1200000000000000000000000000000000000000000000000000000000000000_bytes32};
    const auto loc2{0x1400000000000000000000000000000000000000000000000000000000000000_bytes32};
    const auto loc3{0x3000000000000000000000000000000000000000000000000000000000E00000_bytes32};
    const auto loc4{0x3000000000000000000000000000000000000000000000000000000000E00001_bytes32};

    const auto val1{*from_hex("0x42")};
    const auto val2{*from_hex("0x01")};
    const auto val3{*from_hex("0x127a89")};
    const auto val4{*from_hex("0x05")};

    auto hashed_storage{db::open_cursor(txn, db::table::kHashedStorage)};

    db::upsert_storage_value(hashed_storage, storage_key, loc1, val1);
    db::upsert_storage_value(hashed_storage, storage_key, loc2, val2);
    db::upsert_storage_value(hashed_storage, storage_key, loc3, val3);
    db::upsert_storage_value(hashed_storage, storage_key, loc4, val4);

    HashBuilder storage_hb;

    Bytes value_rlp;
    rlp::encode(value_rlp, val1);
    storage_hb.add_leaf(unpack_nibbles(loc1), value_rlp);
    value_rlp.clear();
    rlp::encode(value_rlp, val2);
    storage_hb.add_leaf(unpack_nibbles(loc2), value_rlp);
    value_rlp.clear();
    rlp::encode(value_rlp, val3);
    storage_hb.add_leaf(unpack_nibbles(loc3), value_rlp);
    value_rlp.clear();
    rlp::encode(value_rlp, val4);
    storage_hb.add_leaf(unpack_nibbles(loc4), value_rlp);

    return storage_hb.root_hash();
}

static std::map<Bytes, Node> read_all_nodes(mdbx::cursor& cursor) {
    cursor.to_first(/*throw_notfound=*/false);
    std::map<Bytes, Node> out;
    db::WalkFunc save_nodes{[&out](mdbx::cursor&, mdbx::cursor::move_result& entry) {
        const Node node{*unmarshal_node(db::from_slice(entry.value))};
        out.emplace(db::from_slice(entry.key), node);
        return true;
    }};
    db::cursor_for_each(cursor, save_nodes);
    return out;
}

TEST_CASE("Account and storage trie") {
    test::Context context;
    auto& txn{context.txn()};

    // ----------------------------------------------------------------
    // Set up test accounts according to the example
    // in the big comment in intermediate_hashes.hpp
    // ----------------------------------------------------------------

    auto hashed_accounts{db::open_cursor(txn, db::table::kHashedAccounts)};

    HashBuilder hb;

    const auto key1{0xB000000000000000000000000000000000000000000000000000000000000000_bytes32};
    const Account a1{0, 3 * kEther};
    hashed_accounts.upsert(db::to_slice(key1), db::to_slice(a1.encode_for_storage()));
    hb.add_leaf(unpack_nibbles(key1), a1.rlp(/*storage_root=*/kEmptyRoot));

    // Some address whose hash starts with 0xB040
    const auto address2{0x7db3e81b72d2695e19764583f6d219dbee0f35ca_address};
    const auto key2{keccak256(address2)};
    REQUIRE((key2.bytes[0] == 0xB0 && key2.bytes[1] == 0x40));
    const Account a2{0, 1 * kEther};
    hashed_accounts.upsert(db::to_slice(key2.bytes), db::to_slice(a2.encode_for_storage()));
    hb.add_leaf(unpack_nibbles(key2.bytes), a2.rlp(/*storage_root=*/kEmptyRoot));

    // Some address whose hash starts with 0xB041
    const auto address3{0x16b07afd1c635f77172e842a000ead9a2a222459_address};
    const auto key3{keccak256(address3)};
    REQUIRE((key3.bytes[0] == 0xB0 && key3.bytes[1] == 0x41));
    const auto code_hash{0x5be74cad16203c4905c068b012a2e9fb6d19d036c410f16fd177f337541440dd_bytes32};
    const Account a3{0, 2 * kEther, code_hash, kDefaultIncarnation};
    hashed_accounts.upsert(db::to_slice(key3.bytes), db::to_slice(a3.encode_for_storage()));

    Bytes storage_key{db::storage_prefix(key3.bytes, kDefaultIncarnation)};
    const evmc::bytes32 storage_root{setup_storage(txn, storage_key)};

    hb.add_leaf(unpack_nibbles(key3.bytes), a3.rlp(storage_root));

    const auto key4a{0xB1A0000000000000000000000000000000000000000000000000000000000000_bytes32};
    const Account a4a{0, 4 * kEther};
    hashed_accounts.upsert(db::to_slice(key4a), db::to_slice(a4a.encode_for_storage()));
    hb.add_leaf(unpack_nibbles(key4a), a4a.rlp(/*storage_root=*/kEmptyRoot));

    const auto key5{0xB310000000000000000000000000000000000000000000000000000000000000_bytes32};
    const Account a5{0, 8 * kEther};
    hashed_accounts.upsert(db::to_slice(key5), db::to_slice(a5.encode_for_storage()));
    hb.add_leaf(unpack_nibbles(key5), a5.rlp(/*storage_root=*/kEmptyRoot));

    const auto key6{0xB340000000000000000000000000000000000000000000000000000000000000_bytes32};
    const Account a6{0, 1 * kEther};
    hashed_accounts.upsert(db::to_slice(key6), db::to_slice(a6.encode_for_storage()));
    hb.add_leaf(unpack_nibbles(key6), a6.rlp(/*storage_root=*/kEmptyRoot));

    // ----------------------------------------------------------------
    // Populate account & storage trie DB tables
    // ----------------------------------------------------------------

    const evmc::bytes32 expected_root{hb.root_hash()};
    regenerate_intermediate_hashes(txn, context.dir().etl().path(), &expected_root);

    // ----------------------------------------------------------------
    // Check account trie
    // ----------------------------------------------------------------

    auto account_trie{db::open_cursor(txn, db::table::kTrieOfAccounts)};

    std::map<Bytes, Node> node_map{read_all_nodes(account_trie)};
    CHECK(node_map.size() == 2);

    const Node node1a{node_map.at(nibbles_from_hex("B"))};

    CHECK(0b1011 == node1a.state_mask());
    CHECK(0b0001 == node1a.tree_mask());
    CHECK(0b1001 == node1a.hash_mask());

    CHECK(node1a.root_hash() == std::nullopt);
    CHECK(node1a.hashes().size() == 2);

    const Node node2a{node_map.at(nibbles_from_hex("B0"))};

    CHECK(0b10001 == node2a.state_mask());
    CHECK(0b00000 == node2a.tree_mask());
    CHECK(0b10000 == node2a.hash_mask());

    CHECK(node2a.root_hash() == std::nullopt);
    CHECK(node2a.hashes().size() == 1);

    // ----------------------------------------------------------------
    // Check storage trie
    // ----------------------------------------------------------------

    auto storage_trie{db::open_cursor(txn, db::table::kTrieOfStorage)};

    node_map = read_all_nodes(storage_trie);
    CHECK(node_map.size() == 1);

    const Node node3{node_map.at(storage_key)};

    CHECK(0b1010 == node3.state_mask());
    CHECK(0b0000 == node3.tree_mask());
    CHECK(0b0010 == node3.hash_mask());

    CHECK(node3.root_hash() == storage_root);
    CHECK(node3.hashes().size() == 1);

    // ----------------------------------------------------------------
    // Add an account
    // ----------------------------------------------------------------

    // Some address whose hash starts with 0xB1
    const auto address4b{0x4f61f2d5ebd991b85aa1677db97307caf5215c91_address};
    const auto key4b{keccak256(address4b)};
    REQUIRE(key4b.bytes[0] == key4a.bytes[0]);

    const Account a4b{0, 5 * kEther};
    hashed_accounts.upsert(db::to_slice(key4b.bytes), db::to_slice(a4b.encode_for_storage()));

    auto account_change_table{db::open_cursor(txn, db::table::kAccountChangeSet)};
    account_change_table.upsert(db::to_slice(db::block_key(1)), db::to_slice(address4b));

    increment_intermediate_hashes(txn, context.dir().etl().path(), /*from=*/0);

    node_map = read_all_nodes(account_trie);
    CHECK(node_map.size() == 2);

    const Node node1b{node_map.at(nibbles_from_hex("B"))};
    CHECK(0b1011 == node1b.state_mask());
    CHECK(0b0001 == node1b.tree_mask());
    CHECK(0b1011 == node1b.hash_mask());

    CHECK(node1b.root_hash() == std::nullopt);

    REQUIRE(node1b.hashes().size() == 3);
    CHECK(node1a.hashes()[0] == node1b.hashes()[0]);
    CHECK(node1a.hashes()[1] == node1b.hashes()[2]);

    const Node node2b{node_map.at(nibbles_from_hex("B0"))};
    CHECK(node2a == node2b);

    SECTION("Delete an account") {
        hashed_accounts.erase(db::to_slice(key2.bytes));
        account_change_table.upsert(db::to_slice(db::block_key(2)), db::to_slice(address2));

        increment_intermediate_hashes(txn, context.dir().etl().path(), /*from=*/1);

        node_map = read_all_nodes(account_trie);
        CHECK(node_map.size() == 1);

        const Node node1c{node_map.at(nibbles_from_hex("B"))};
        CHECK(0b1011 == node1c.state_mask());
        CHECK(0b0000 == node1c.tree_mask());
        CHECK(0b1011 == node1c.hash_mask());

        CHECK(node1c.root_hash() == std::nullopt);

        REQUIRE(node1c.hashes().size() == 3);
        CHECK(node1b.hashes()[0] != node1c.hashes()[0]);
        CHECK(node1b.hashes()[1] == node1c.hashes()[1]);
        CHECK(node1b.hashes()[2] == node1c.hashes()[2]);
    }

    SECTION("Delete several accounts") {
        hashed_accounts.erase(db::to_slice(key2.bytes));
        account_change_table.upsert(db::to_slice(db::block_key(2)), db::to_slice(address2));

        hashed_accounts.erase(db::to_slice(key3.bytes));
        account_change_table.upsert(db::to_slice(db::block_key(2)), db::to_slice(address3));

        increment_intermediate_hashes(txn, context.dir().etl().path(), /*from=*/1);

        node_map = read_all_nodes(account_trie);
        CHECK(node_map.size() == 1);

        const Node node1c{node_map.at(nibbles_from_hex("B"))};
        CHECK(0b1011 == node1c.state_mask());
        CHECK(0b0000 == node1c.tree_mask());
        CHECK(0b1010 == node1c.hash_mask());

        CHECK(node1c.root_hash() == std::nullopt);

        REQUIRE(node1c.hashes().size() == 2);
        CHECK(node1b.hashes()[1] == node1c.hashes()[0]);
        CHECK(node1b.hashes()[2] == node1c.hashes()[1]);
    }
}

TEST_CASE("Account trie around extension node") {
    const Account a{0, 1 * kEther};

    const std::vector<evmc::bytes32> keys{
        0x30af561000000000000000000000000000000000000000000000000000000000_bytes32,
        0x30af569000000000000000000000000000000000000000000000000000000000_bytes32,
        0x30af650000000000000000000000000000000000000000000000000000000000_bytes32,
        0x30af6f0000000000000000000000000000000000000000000000000000000000_bytes32,
        0x30af8f0000000000000000000000000000000000000000000000000000000000_bytes32,
        0x3100000000000000000000000000000000000000000000000000000000000000_bytes32,
    };

    test::Context context;
    auto& txn{context.txn()};

    auto hashed_accounts{db::open_cursor(txn, db::table::kHashedAccounts)};
    HashBuilder hb;

    for (const auto& key : keys) {
        hashed_accounts.upsert(db::to_slice(key), db::to_slice(a.encode_for_storage()));
        hb.add_leaf(unpack_nibbles(key), a.rlp(/*storage_root=*/kEmptyRoot));
    }

    const evmc::bytes32 expected_root{hb.root_hash()};
    CHECK(regenerate_intermediate_hashes(txn, context.dir().etl().path()) == expected_root);

    auto account_trie{db::open_cursor(txn, db::table::kTrieOfAccounts)};

    std::map<Bytes, Node> node_map{read_all_nodes(account_trie)};
    CHECK(node_map.size() == 2);

    const Node node1{node_map.at(nibbles_from_hex("3"))};

    CHECK(0b11 == node1.state_mask());
    CHECK(0b01 == node1.tree_mask());
    CHECK(0b00 == node1.hash_mask());

    CHECK(node1.root_hash() == std::nullopt);
    CHECK(node1.hashes().empty());

    const Node node2{node_map.at(nibbles_from_hex("30af"))};

    CHECK(0b101100000 == node2.state_mask());
    CHECK(0b000000000 == node2.tree_mask());
    CHECK(0b001000000 == node2.hash_mask());

    CHECK(node2.root_hash() == std::nullopt);
    CHECK(node2.hashes().size() == 1);
}

static evmc::address int_to_address(uint64_t i) {
    uint8_t be[8];
    endian::store_big_u64(be, i);
    return to_evmc_address(be);
}

static evmc::bytes32 int_to_bytes32(uint64_t i) {
    uint8_t be[8];
    endian::store_big_u64(be, i);
    return to_bytes32(be);
}

TEST_CASE("Incremental vs regeneration") {
    test::Context context;
    auto& txn{context.txn()};

    static constexpr size_t n{10'000};

    auto hashed_accounts{db::open_cursor(txn, db::table::kHashedAccounts)};
    auto account_change_table{db::open_cursor(txn, db::table::kAccountChangeSet)};
    auto account_trie{db::open_cursor(txn, db::table::kTrieOfAccounts)};

    // ------------------------------------------------------------------------------
    // Take A: create some accounts at genesis and then apply some changes at Block 1
    // ------------------------------------------------------------------------------

    // Start with 3n accounts at genesis, each holding 1 ETH
    static constexpr Account one_eth{0, 1 * kEther};
    for (size_t i{0}; i < 3 * n; ++i) {
        const evmc::address address{int_to_address(i)};
        const auto hash{keccak256(address)};
        hashed_accounts.upsert(db::to_slice(hash.bytes), db::to_slice(one_eth.encode_for_storage()));
    }

    regenerate_intermediate_hashes(txn, context.dir().etl().path());

    static const Bytes block_key{db::block_key(1)};

    // Double the balance of the first third of the accounts
    static constexpr Account two_eth{0, 2 * kEther};
    for (size_t i{0}; i < n; ++i) {
        const evmc::address address{int_to_address(i)};
        const auto hash{keccak256(address)};
        hashed_accounts.upsert(db::to_slice(hash.bytes), db::to_slice(two_eth.encode_for_storage()));
        account_change_table.upsert(db::to_slice(block_key), db::to_slice(address));
    }

    // Delete the second third of the accounts
    for (size_t i{n}; i < 2 * n; ++i) {
        const evmc::address address{int_to_address(i)};
        const auto hash{keccak256(address)};
        hashed_accounts.erase(db::to_slice(hash.bytes));
        account_change_table.upsert(db::to_slice(block_key), db::to_slice(address));
    }

    // Don't touch the last third of genesis accounts

    // And add some new accounts, each holding 1 ETH
    for (size_t i{3 * n}; i < 4 * n; ++i) {
        const evmc::address address{int_to_address(i)};
        const auto hash{keccak256(address)};
        hashed_accounts.upsert(db::to_slice(hash.bytes), db::to_slice(one_eth.encode_for_storage()));
        account_change_table.upsert(db::to_slice(block_key), db::to_slice(address));
    }

    const auto incremental_root{increment_intermediate_hashes(txn, context.dir().etl().path(), /*from=*/0)};

    const std::map<Bytes, Node> incremental_nodes{read_all_nodes(account_trie)};

    // ------------------------------------------------------------------------------
    // Take B: generate intermediate hashes for the accounts as of Block 1 in one go,
    // without increment_intermediate_hashes
    // ------------------------------------------------------------------------------
    txn.clear_map(db::open_map(txn, db::table::kHashedAccounts));
    txn.clear_map(db::open_map(txn, db::table::kAccountChangeSet));

    // Accounts [0,n) now hold 2 ETH
    for (size_t i{0}; i < n; ++i) {
        const evmc::address address{int_to_address(i)};
        const auto hash{keccak256(address)};
        hashed_accounts.upsert(db::to_slice(hash.bytes), db::to_slice(two_eth.encode_for_storage()));
    }

    // Accounts [n,2n) are deleted

    // Accounts [2n,4n) hold 1 ETH
    for (size_t i{2 * n}; i < 4 * n; ++i) {
        const evmc::address address{int_to_address(i)};
        const auto hash{keccak256(address)};
        hashed_accounts.upsert(db::to_slice(hash.bytes), db::to_slice(one_eth.encode_for_storage()));
    }

    const auto fused_root{regenerate_intermediate_hashes(txn, context.dir().etl().path())};

    const std::map<Bytes, Node> fused_nodes{read_all_nodes(account_trie)};

    // ------------------------------------------------------------------------------
    // A and B should yield the same result
    // ------------------------------------------------------------------------------
    CHECK(fused_root == incremental_root);
    CHECK(fused_nodes == incremental_nodes);
}

TEST_CASE("Incremental vs regeneration for storage") {
    test::Context context;
    auto& txn{context.txn()};

    // TODO (Andrew) n = 2000 triggers AddressSanitizer: use-after-poison in MDBX
    static constexpr size_t n{1'000};

    auto hashed_accounts{db::open_cursor(txn, db::table::kHashedAccounts)};
    auto hashed_storage{db::open_cursor(txn, db::table::kHashedStorage)};
    auto storage_change_table{db::open_cursor(txn, db::table::kStorageChangeSet)};
    auto storage_trie{db::open_cursor(txn, db::table::kTrieOfStorage)};

    static constexpr uint64_t incarnation1{3};
    static constexpr uint64_t incarnation2{1};

    static constexpr Account account1{
        5,                                                                           // nonce
        7 * kEther,                                                                  // balance
        0x5e3c5ae99a1c6785210d0d233641562557ad763e18907cca3a8d42bd0a0b4ecb_bytes32,  // code_hash
        incarnation1,                                                                // incarnation
    };

    static constexpr Account account2{
        1,                                                                           // nonce
        13 * kEther,                                                                 // balance
        0x3a9c1d84e48734ae951e023197bda6d03933a4ca44124a2a544e227aa93efe75_bytes32,  // code_hash
        incarnation2,                                                                // incarnation
    };

    static constexpr auto address1{0x1000000000000000000000000000000000000000_address};
    static constexpr auto address2{0x2000000000000000000000000000000000000000_address};

    static const auto hashed_address1{keccak256(address1)};
    static const auto hashed_address2{keccak256(address2)};

    hashed_accounts.upsert(db::to_slice(hashed_address1.bytes), db::to_slice(account1.encode_for_storage()));
    hashed_accounts.upsert(db::to_slice(hashed_address2.bytes), db::to_slice(account2.encode_for_storage()));

    static const Bytes storage_prefix1{db::storage_prefix(hashed_address1.bytes, incarnation1)};
    static const Bytes storage_prefix2{db::storage_prefix(hashed_address2.bytes, incarnation2)};

    static const Bytes storage_change_key1{db::storage_change_key(/*block_number=*/1, address1, incarnation1)};
    static const Bytes storage_change_key2{db::storage_change_key(/*block_number=*/1, address2, incarnation2)};

    const auto upsert_storage_for_two_test_accounts = [&](size_t i, ByteView value, bool register_change) {
        const evmc::bytes32 plain_loc1{int_to_bytes32(2 * i)};
        const evmc::bytes32 plain_loc2{int_to_bytes32(2 * i + 1)};
        const auto hashed_loc1{keccak256(plain_loc1)};
        const auto hashed_loc2{keccak256(plain_loc2)};
        db::upsert_storage_value(hashed_storage, storage_prefix1, hashed_loc1.bytes, value);
        db::upsert_storage_value(hashed_storage, storage_prefix2, hashed_loc2.bytes, value);
        if (register_change) {
            storage_change_table.upsert(db::to_slice(storage_change_key1), db::to_slice(plain_loc1.bytes));
            storage_change_table.upsert(db::to_slice(storage_change_key2), db::to_slice(plain_loc2.bytes));
        }
    };

    // ------------------------------------------------------------------------------
    // Take A: create some storage at genesis and then apply some changes at Block 1
    // ------------------------------------------------------------------------------

    // Start with 3n storage slots per account at genesis, each with the same value
    static const Bytes value_x{*from_hex("42")};
    for (size_t i{0}; i < 3 * n; ++i) {
        upsert_storage_for_two_test_accounts(i, value_x, false);
    }

    regenerate_intermediate_hashes(txn, context.dir().etl().path());

    // Change the value of the first third of the storage
    static const Bytes value_y{*from_hex("71f602b294119bf452f1923814f5c6de768221254d3056b1bd63e72dc3142a29")};
    for (size_t i{0}; i < n; ++i) {
        upsert_storage_for_two_test_accounts(i, value_y, true);
    }

    // Delete the second third of the storage
    for (size_t i{n}; i < 2 * n; ++i) {
        upsert_storage_for_two_test_accounts(i, {}, true);
    }

    // Don't touch the last third of genesis storage

    // And add some new storage
    for (size_t i{3 * n}; i < 4 * n; ++i) {
        upsert_storage_for_two_test_accounts(i, value_x, true);
    }

    const auto incremental_root{increment_intermediate_hashes(txn, context.dir().etl().path(), /*from=*/0)};

    const std::map<Bytes, Node> incremental_nodes{read_all_nodes(storage_trie)};

    // ------------------------------------------------------------------------------
    // Take B: generate intermediate hashes for the storage as of Block 1 in one go,
    // without increment_intermediate_hashes
    // ------------------------------------------------------------------------------
    txn.clear_map(db::open_map(txn, db::table::kHashedStorage));
    txn.clear_map(db::open_map(txn, db::table::kStorageChangeSet));

    // The first third of the storage now has value_y
    for (size_t i{0}; i < n; ++i) {
        upsert_storage_for_two_test_accounts(i, value_y, false);
    }

    // The second third of the storage is deleted

    // The last third and the extra storage has value_x
    for (size_t i{2 * n}; i < 4 * n; ++i) {
        upsert_storage_for_two_test_accounts(i, value_x, false);
    }

    const auto fused_root{regenerate_intermediate_hashes(txn, context.dir().etl().path())};

    const std::map<Bytes, Node> fused_nodes{read_all_nodes(storage_trie)};

    // ------------------------------------------------------------------------------
    // A and B should yield the same result
    // ------------------------------------------------------------------------------
    CHECK(fused_root == incremental_root);
    CHECK(fused_nodes == incremental_nodes);
}

TEST_CASE("Storage deletion") {
    test::Context context;
    auto& txn{context.txn()};

    static constexpr auto address{0x1000000000000000000000000000000000000000_address};
    static const auto hashed_address{keccak256(address)};

    static constexpr Account account{
        1,                                                                           // nonce
        15 * kEther,                                                                 // balance
        0x7792ad513ce4d8f49163e21b25bf27ce6c8a0fa1e78c564e7d20a2d303303ba0_bytes32,  // code_hash
        kDefaultIncarnation,                                                         // incarnation
    };

    auto hashed_accounts{db::open_cursor(txn, db::table::kHashedAccounts)};
    auto hashed_storage{db::open_cursor(txn, db::table::kHashedStorage)};
    auto storage_change_table{db::open_cursor(txn, db::table::kStorageChangeSet)};
    auto storage_trie{db::open_cursor(txn, db::table::kTrieOfStorage)};

    hashed_accounts.upsert(db::to_slice(hashed_address.bytes), db::to_slice(account.encode_for_storage()));

    static constexpr auto plain_location1{0x1000000000000000000000000000000000000000000000000000000000000000_bytes32};
    static constexpr auto plain_location2{0x1A00000000000000000000000000000000000000000000000000000000000000_bytes32};
    static constexpr auto plain_location3{0x1E00000000000000000000000000000000000000000000000000000000000000_bytes32};

    static const auto hashed_location1{keccak256(plain_location1)};
    static const auto hashed_location2{keccak256(plain_location2)};
    static const auto hashed_location3{keccak256(plain_location3)};

    static const Bytes value1{*from_hex("0xABCD")};
    static const Bytes value2{*from_hex("0x4321")};
    static const Bytes value3{*from_hex("0x4444")};

    static const Bytes storage_prefix{db::storage_prefix(hashed_address.bytes, kDefaultIncarnation)};

    db::upsert_storage_value(hashed_storage, storage_prefix, hashed_location1.bytes, value1);
    db::upsert_storage_value(hashed_storage, storage_prefix, hashed_location2.bytes, value2);
    db::upsert_storage_value(hashed_storage, storage_prefix, hashed_location3.bytes, value3);

    regenerate_intermediate_hashes(txn, context.dir().etl().path());

    // There should be one root node in storage trie
    const std::map<Bytes, Node> nodes_a{read_all_nodes(storage_trie)};
    CHECK(nodes_a.size() == 1);

    SECTION("Increment the trie without any changes") {
        increment_intermediate_hashes(txn, context.dir().etl().path(), /*from=*/0);
        const std::map<Bytes, Node> nodes_b{read_all_nodes(storage_trie)};
        CHECK(nodes_b == nodes_a);
    }

    SECTION("Delete storage and increment the trie") {
        db::upsert_storage_value(hashed_storage, storage_prefix, hashed_location1.bytes, {});
        db::upsert_storage_value(hashed_storage, storage_prefix, hashed_location2.bytes, {});
        db::upsert_storage_value(hashed_storage, storage_prefix, hashed_location3.bytes, {});

        static const Bytes storage_change_key{db::storage_change_key(/*block_number=*/1, address, kDefaultIncarnation)};

        storage_change_table.upsert(db::to_slice(storage_change_key), db::to_slice(plain_location1.bytes));
        storage_change_table.upsert(db::to_slice(storage_change_key), db::to_slice(plain_location2.bytes));
        storage_change_table.upsert(db::to_slice(storage_change_key), db::to_slice(plain_location3.bytes));

        increment_intermediate_hashes(txn, context.dir().etl().path(), /*from=*/0);
        const std::map<Bytes, Node> nodes_b{read_all_nodes(storage_trie)};
        CHECK(nodes_b.empty());
    }
}

TEST_CASE("increment_key") {
    CHECK(increment_key({}) == std::nullopt);
    CHECK(nibbles_to_hex(*increment_key(nibbles_from_hex("12"))) == "13");
    CHECK(nibbles_to_hex(*increment_key(nibbles_from_hex("1F"))) == "20");
    CHECK(increment_key(nibbles_from_hex("FF")) == std::nullopt);
    CHECK(nibbles_to_hex(*increment_key(nibbles_from_hex("120"))) == "121");
    CHECK(nibbles_to_hex(*increment_key(nibbles_from_hex("12E"))) == "12F");
    CHECK(nibbles_to_hex(*increment_key(nibbles_from_hex("12F"))) == "130");
    CHECK(nibbles_to_hex(*increment_key(nibbles_from_hex("1FF"))) == "200");
    CHECK(increment_key(nibbles_from_hex("FFF")) == std::nullopt);
}

}  // namespace silkworm::trie
