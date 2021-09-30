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

#include "intermediate_hashes.hpp"

#include <catch2/catch.hpp>

#include <silkworm/common/directories.hpp>
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

TEST_CASE("AccountTrieCursor traversal") {
    const TemporaryDirectory tmp_dir;
    DataDirectory data_dir{tmp_dir.path()};
    data_dir.deploy();

    db::EnvConfig db_config{data_dir.chaindata().path().string(), /*create*/ true};
    db_config.inmemory = true;
    auto env{db::open_env(db_config)};
    auto txn{env.start_write()};
    db::table::create_all(txn);

    auto account_trie{db::open_cursor(txn, db::table::kTrieOfAccounts)};

    const Bytes key1{nibbles_from_hex("1")};
    const Node node1{/*state_mask=*/0b111, /*tree_mask=*/0b101, /*hash_mask=*/0, /*hashes=*/{}};
    account_trie.upsert(db::to_slice(key1), db::to_slice(marshal_node(node1)));

    const Bytes key2{nibbles_from_hex("10B")};
    const Node node2{/*state_mask=*/0b1010, /*tree_mask=*/0, /*hash_mask=*/0, /*hashes=*/{}};
    account_trie.upsert(db::to_slice(key2), db::to_slice(marshal_node(node2)));

    const Bytes key3{nibbles_from_hex("13")};
    const Node node3{/*state_mask=*/0b1110, /*tree_mask=*/0, /*hash_mask=*/0, /*hashes=*/{}};
    account_trie.upsert(db::to_slice(key3), db::to_slice(marshal_node(node3)));

    PrefixSet changed;
    AccountTrieCursor atc{txn, changed};

    // Traversal should be in pre-order:
    // 1. Visit the current node
    // 2. Recursively traverse the current node's left subtree.
    // 3. Recursively traverse the current node's right subtree.
    // https://en.wikipedia.org/wiki/Tree_traversal#Pre-order,_NLR

    // Only nibbles with state flag should be traversed.

    CHECK((atc.key() != std::nullopt && atc.key()->empty()));  // root

    atc.next(/*skip_children=*/false);
    CHECK(nibbles_to_hex(*atc.key()) == "10");
    atc.next(/*skip_children=*/false);
    CHECK(nibbles_to_hex(*atc.key()) == "10B1");
    atc.next(/*skip_children=*/false);
    CHECK(nibbles_to_hex(*atc.key()) == "10B3");
    atc.next(/*skip_children=*/false);
    CHECK(nibbles_to_hex(*atc.key()) == "11");
    atc.next(/*skip_children=*/false);
    CHECK(nibbles_to_hex(*atc.key()) == "12");
    atc.next(/*skip_children=*/false);
    CHECK(nibbles_to_hex(*atc.key()) == "131");
    atc.next(/*skip_children=*/false);
    CHECK(nibbles_to_hex(*atc.key()) == "132");
    atc.next(/*skip_children=*/false);
    CHECK(nibbles_to_hex(*atc.key()) == "133");

    atc.next(/*skip_children=*/false);
    CHECK(atc.key() == std::nullopt);  // end of trie
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

    Bytes data1{full_view(loc1)};
    data1.append(val1);
    hashed_storage.upsert(db::to_slice(storage_key), db::to_slice(data1));
    Bytes data2{full_view(loc2)};
    data2.append(val2);
    hashed_storage.upsert(db::to_slice(storage_key), db::to_slice(data2));
    Bytes data3{full_view(loc3)};
    data3.append(val3);
    hashed_storage.upsert(db::to_slice(storage_key), db::to_slice(data3));
    Bytes data4{full_view(loc4)};
    data4.append(val4);
    hashed_storage.upsert(db::to_slice(storage_key), db::to_slice(data4));

    HashBuilder storage_hb;

    Bytes value_rlp;
    rlp::encode(value_rlp, val1);
    storage_hb.add_leaf(unpack_nibbles(full_view(loc1)), value_rlp);
    value_rlp.clear();
    rlp::encode(value_rlp, val2);
    storage_hb.add_leaf(unpack_nibbles(full_view(loc2)), value_rlp);
    value_rlp.clear();
    rlp::encode(value_rlp, val3);
    storage_hb.add_leaf(unpack_nibbles(full_view(loc3)), value_rlp);
    value_rlp.clear();
    rlp::encode(value_rlp, val4);
    storage_hb.add_leaf(unpack_nibbles(full_view(loc4)), value_rlp);

    return storage_hb.root_hash();
}

static std::map<Bytes, Node> read_all_nodes(mdbx::cursor& cursor) {
    cursor.to_first();
    std::map<Bytes, Node> out;
    const auto save_nodes{[&out](mdbx::cursor::move_result& entry) {
        const Node node{*unmarshal_node(db::from_slice(entry.value))};
        out.emplace(db::from_slice(entry.key), node);
        return true;
    }};
    db::for_each(cursor, save_nodes);
    return out;
}

TEST_CASE("Account and storage trie") {
    const TemporaryDirectory tmp_dir;
    DataDirectory data_dir{tmp_dir.path()};
    data_dir.deploy();

    // Initialize temporary Database
    db::EnvConfig db_config{data_dir.chaindata().path().string(), /*create*/ true};
    db_config.inmemory = true;
    auto env{db::open_env(db_config)};
    auto txn{env.start_write()};
    db::table::create_all(txn);

    // ----------------------------------------------------------------
    // Set up test accounts according to the example
    // in the big comment in intermediate_hashes.hpp
    // ----------------------------------------------------------------

    auto hashed_accounts{db::open_cursor(txn, db::table::kHashedAccounts)};

    HashBuilder hb;

    const auto key1{0xB000000000000000000000000000000000000000000000000000000000000000_bytes32};
    const Account a1{0, 3 * kEther};
    hashed_accounts.upsert(db::to_slice(key1), db::to_slice(a1.encode_for_storage()));
    hb.add_leaf(unpack_nibbles(full_view(key1)), a1.rlp(/*storage_root=*/kEmptyRoot));

    // Some address whose hash starts with 0xB040
    const auto address2{0x7db3e81b72d2695e19764583f6d219dbee0f35ca_address};
    const auto key2{keccak256(full_view(address2))};
    REQUIRE((key2.bytes[0] == 0xB0 && key2.bytes[1] == 0x40));
    const Account a2{0, 1 * kEther};
    hashed_accounts.upsert(mdbx::slice{key2.bytes, kHashLength}, db::to_slice(a2.encode_for_storage()));
    hb.add_leaf(unpack_nibbles(full_view(key2.bytes)), a2.rlp(/*storage_root=*/kEmptyRoot));

    // Some address whose hash starts with 0xB041
    const auto address3{0x16b07afd1c635f77172e842a000ead9a2a222459_address};
    const auto key3{keccak256(full_view(address3))};
    REQUIRE((key3.bytes[0] == 0xB0 && key3.bytes[1] == 0x41));
    const auto code_hash{0x5be74cad16203c4905c068b012a2e9fb6d19d036c410f16fd177f337541440dd_bytes32};
    const Account a3{0, 2 * kEther, code_hash, kDefaultIncarnation};
    hashed_accounts.upsert(mdbx::slice{key3.bytes, kHashLength}, db::to_slice(a3.encode_for_storage()));

    Bytes storage_key{db::storage_prefix(full_view(key3.bytes), kDefaultIncarnation)};
    const evmc::bytes32 storage_root{setup_storage(txn, storage_key)};

    hb.add_leaf(unpack_nibbles(full_view(key3.bytes)), a3.rlp(storage_root));

    const auto key4a{0xB1A0000000000000000000000000000000000000000000000000000000000000_bytes32};
    const Account a4a{0, 4 * kEther};
    hashed_accounts.upsert(db::to_slice(key4a), db::to_slice(a4a.encode_for_storage()));
    hb.add_leaf(unpack_nibbles(full_view(key4a)), a4a.rlp(/*storage_root=*/kEmptyRoot));

    const auto key5{0xB310000000000000000000000000000000000000000000000000000000000000_bytes32};
    const Account a5{0, 8 * kEther};
    hashed_accounts.upsert(db::to_slice(key5), db::to_slice(a5.encode_for_storage()));
    hb.add_leaf(unpack_nibbles(full_view(key5)), a5.rlp(/*storage_root=*/kEmptyRoot));

    const auto key6{0xB340000000000000000000000000000000000000000000000000000000000000_bytes32};
    const Account a6{0, 1 * kEther};
    hashed_accounts.upsert(db::to_slice(key6), db::to_slice(a6.encode_for_storage()));
    hb.add_leaf(unpack_nibbles(full_view(key6)), a6.rlp(/*storage_root=*/kEmptyRoot));

    // ----------------------------------------------------------------
    // Populate account & storage trie DB tables
    // ----------------------------------------------------------------

    const evmc::bytes32 expected_root{hb.root_hash()};
    regenerate_intermediate_hashes(txn, data_dir.etl().path(), &expected_root);

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
    const auto key4b{keccak256(full_view(address4b))};
    REQUIRE(key4b.bytes[0] == key4a.bytes[0]);

    const Account a4b{0, 5 * kEther};
    hashed_accounts.upsert(mdbx::slice{key4b.bytes, kHashLength}, db::to_slice(a4b.encode_for_storage()));

    auto account_change_table{db::open_cursor(txn, db::table::kAccountChangeSet)};
    account_change_table.upsert(db::to_slice(db::block_key(1)), db::to_slice(address4b));

    increment_intermediate_hashes(txn, data_dir.etl().path(), /*from=*/0);

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

    // TODO[Issue 179] storage

    SECTION("Delete an account") {
        hashed_accounts.find(mdbx::slice{key2.bytes, kHashLength});
        hashed_accounts.erase();
        account_change_table.upsert(db::to_slice(db::block_key(2)), db::to_slice(address2));

        increment_intermediate_hashes(txn, data_dir.etl().path(), /*from=*/1);

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
        hashed_accounts.find(mdbx::slice{key2.bytes, kHashLength});
        hashed_accounts.erase();
        account_change_table.upsert(db::to_slice(db::block_key(2)), db::to_slice(address2));

        hashed_accounts.find(mdbx::slice{key3.bytes, kHashLength});
        hashed_accounts.erase();
        account_change_table.upsert(db::to_slice(db::block_key(2)), db::to_slice(address3));

        increment_intermediate_hashes(txn, data_dir.etl().path(), /*from=*/1);

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

    const TemporaryDirectory tmp_dir;
    DataDirectory data_dir{tmp_dir.path()};
    data_dir.deploy();

    // Initialize temporary Database
    db::EnvConfig db_config{data_dir.chaindata().path().string(), /*create*/ true};
    db_config.inmemory = true;
    auto env{db::open_env(db_config)};
    auto txn{env.start_write()};
    db::table::create_all(txn);

    auto hashed_accounts{db::open_cursor(txn, db::table::kHashedAccounts)};
    HashBuilder hb;

    for (const auto& key : keys) {
        auto key_view{full_view(key)};
        hashed_accounts.upsert(db::to_slice(key_view), db::to_slice(a.encode_for_storage()));
        hb.add_leaf(unpack_nibbles(key_view), a.rlp(/*storage_root=*/kEmptyRoot));
    }

    const evmc::bytes32 expected_root{hb.root_hash()};
    CHECK(regenerate_intermediate_hashes(txn, data_dir.etl().path()) == expected_root);

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

}  // namespace silkworm::trie
