// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/trie/hash_builder.hpp>
#include <silkworm/core/trie/nibbles.hpp>
#include <silkworm/core/types/account.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/db/datastore/kvdb/etl_mdbx_collector.hpp>
#include <silkworm/db/state/account_codec.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/db/test_util/temp_chain_data.hpp>
#include <silkworm/node/stagedsync/stages/stage_interhashes/trie_cursor.hpp>
#include <silkworm/node/stagedsync/stages/stage_interhashes/trie_loader.hpp>

namespace silkworm::trie {

using namespace silkworm::db;
using namespace silkworm::db::state;
using namespace silkworm::datastore::kvdb;
using datastore::kvdb::Collector;

static ethash::hash256 keccak256(const evmc::address& address) {
    return silkworm::keccak256(address.bytes);
}

TEST_CASE("Trie Cursor") {
    test_util::TempChainData db_context{};
    auto txn{db_context.txn()};

    SECTION("Only root trie no changes") {
        trie::PrefixSet changed_accounts{};
        PooledCursor trie_accounts(txn, table::kTrieOfAccounts);
        trie::TrieCursor ta_cursor{trie_accounts, &changed_accounts};

        Bytes k{};
        Bytes v{*from_hex(
            "0xfffffffffffff587705b56c193a582ba235d2fbc0714369dc24c60df85bb6b010c405d6d4ff1c587157345c796457244932c27c7"
            "2a5b59b2af68229aced2a35c11064fcb52183c3a01330eeb55d1bc5229391d98f1d47677ff57f04aa31bccb2eae0458bf2435fc423"
            "08a6097114f741d87630f06fd8f8ff6b11889389b1f65e2ac07cc239233c896ad842d010f886b4ffbc558eb8dc2f20ad47f0fc082f"
            "c081d1ed1c354d51e1c6c148e00033f6699ff564e316647628c9d9b51204faf3841a6ca538e768be56a17afb284f6a858115b652be"
            "24501d6d8ecce5bf9e0581f19c908584f77db54869d85531ca872cf92d84a3dc3f9bafd302460fc3794ff14ff501e8220f40225561"
            "b133453ccddfdffe47be42f60fa2bccf1da4c067778c48b17f4d5b8ff3de9bf082bed77a58e8b350d503a409ceb9f0816cfe2c172e"
            "6505e2693431e48366118133493304604905a658efcccb180651eefbc857fbc4da230e20e8efe27a68231806d17d5ed83cb3fcf567"
            "e85099023711366935ed021785e4b34c071d5cfc03fa21bc068d956f62ba45516a74739733ff1eadfbd25dce36f25e4dfa8af5327f"
            "67beb3125b34103b14f16d88f9c68fc4516203fad53c3a2c405ef83201fee92bd4fb7cfb1022b46d6507c31957b94580926086c547"
            "b804061bfa46e86139874800ae6d6f9f79097ac8c221e9229d13a45a0864a3fda170863bb6513010e95cfdd3f4bb151c7d242a682a"
            "16041a426bea6de01aa9ed925e80d5fed57c302988")};

        trie_accounts.insert(to_slice(k), to_slice(v));

        auto ta_data{ta_cursor.to_prefix({})};

        REQUIRE((ta_data.key.has_value() == true && ta_data.key.value().empty()));
        REQUIRE(ta_data.first_uncovered.has_value() == false);
        REQUIRE(ta_data.hash.has_value() == true);

        bool has_thrown{false};
        try {
            // Must throw as we're at the end of tree
            ta_data = ta_cursor.to_next();
        } catch (...) {
            has_thrown = true;
        }

        REQUIRE(has_thrown);
    }

    SECTION("Only root trie with changes") {
        trie::PrefixSet changed_accounts{};
        PooledCursor trie_accounts(txn, table::kTrieOfAccounts);
        trie::TrieCursor ta_cursor{trie_accounts, &changed_accounts};

        Bytes k{};
        Bytes v{*from_hex(
            "0xfffffffffffff587705b56c193a582ba235d2fbc0714369dc24c60df85bb6b010c405d6d4ff1c587157345c796457244932c27c7"
            "2a5b59b2af68229aced2a35c11064fcb52183c3a01330eeb55d1bc5229391d98f1d47677ff57f04aa31bccb2eae0458bf2435fc423"
            "08a6097114f741d87630f06fd8f8ff6b11889389b1f65e2ac07cc239233c896ad842d010f886b4ffbc558eb8dc2f20ad47f0fc082f"
            "c081d1ed1c354d51e1c6c148e00033f6699ff564e316647628c9d9b51204faf3841a6ca538e768be56a17afb284f6a858115b652be"
            "24501d6d8ecce5bf9e0581f19c908584f77db54869d85531ca872cf92d84a3dc3f9bafd302460fc3794ff14ff501e8220f40225561"
            "b133453ccddfdffe47be42f60fa2bccf1da4c067778c48b17f4d5b8ff3de9bf082bed77a58e8b350d503a409ceb9f0816cfe2c172e"
            "6505e2693431e48366118133493304604905a658efcccb180651eefbc857fbc4da230e20e8efe27a68231806d17d5ed83cb3fcf567"
            "e85099023711366935ed021785e4b34c071d5cfc03fa21bc068d956f62ba45516a74739733ff1eadfbd25dce36f25e4dfa8af5327f"
            "67beb3125b34103b14f16d88f9c68fc4516203fad53c3a2c405ef83201fee92bd4fb7cfb1022b46d6507c31957b94580926086c547"
            "b804061bfa46e86139874800ae6d6f9f79097ac8c221e9229d13a45a0864a3fda170863bb6513010e95cfdd3f4bb151c7d242a682a"
            "16041a426bea6de01aa9ed925e80d5fed57c302988")};

        trie_accounts.insert(to_slice(k), to_slice(v));
        changed_accounts.insert(*from_hex("0x000001"));

        bool has_thrown{false};
        try {
            // Must throw as it can't find child 00
            (void)ta_cursor.to_prefix({});
        } catch (...) {
            has_thrown = true;
        }

        REQUIRE(has_thrown);
    }

    SECTION("Root + child with changes") {
        Collector collector{db_context.dir().path()};
        trie::PrefixSet changed_accounts{};
        PooledCursor trie_accounts(txn, table::kTrieOfAccounts);
        trie::TrieCursor ta_cursor{trie_accounts, &changed_accounts, &collector};

        Bytes k{};
        Bytes v{*from_hex(
            "0xfffffffffffff587705b56c193a582ba235d2fbc0714369dc24c60df85bb6b010c405d6d4ff1c587157345c796457244932c27c7"
            "2a5b59b2af68229aced2a35c11064fcb52183c3a01330eeb55d1bc5229391d98f1d47677ff57f04aa31bccb2eae0458bf2435fc423"
            "08a6097114f741d87630f06fd8f8ff6b11889389b1f65e2ac07cc239233c896ad842d010f886b4ffbc558eb8dc2f20ad47f0fc082f"
            "c081d1ed1c354d51e1c6c148e00033f6699ff564e316647628c9d9b51204faf3841a6ca538e768be56a17afb284f6a858115b652be"
            "24501d6d8ecce5bf9e0581f19c908584f77db54869d85531ca872cf92d84a3dc3f9bafd302460fc3794ff14ff501e8220f40225561"
            "b133453ccddfdffe47be42f60fa2bccf1da4c067778c48b17f4d5b8ff3de9bf082bed77a58e8b350d503a409ceb9f0816cfe2c172e"
            "6505e2693431e48366118133493304604905a658efcccb180651eefbc857fbc4da230e20e8efe27a68231806d17d5ed83cb3fcf567"
            "e85099023711366935ed021785e4b34c071d5cfc03fa21bc068d956f62ba45516a74739733ff1eadfbd25dce36f25e4dfa8af5327f"
            "67beb3125b34103b14f16d88f9c68fc4516203fad53c3a2c405ef83201fee92bd4fb7cfb1022b46d6507c31957b94580926086c547"
            "b804061bfa46e86139874800ae6d6f9f79097ac8c221e9229d13a45a0864a3fda170863bb6513010e95cfdd3f4bb151c7d242a682a"
            "16041a426bea6de01aa9ed925e80d5fed57c302988")};
        trie_accounts.insert(to_slice(k), to_slice(v));

        k = *from_hex("0x00");
        v = *from_hex(
            "0xffffffffffff061d711a452d9137600bc9a5fecb8fa8f4fe4496f232b0ec706c8fb601beff0b2652e642a62b64789a2565026172"
            "91e721c0b453fa9eac8d542ca04cb2867db59bcb89ce69e4e2ad0185e51482de826109c36f2cabd186fcbb4015d6ec43d6ee0a3baa"
            "8f90bb26daa90b18dbf4f7b256f3c847119b3ede4ce02d1ad5af1b05629be35bcaecab86eb1e15b0797d802cbb6c2c515e53abbc8c"
            "34e8b747089be40fceff32a5c0c2a5d115cb07f3bc86e14e90fb9538da1522a0ceddc6ee989c514ae54aebfbfe2d3d61bc48e46d09"
            "022477e184e44597b36be491d1dad83dc8ce00e81b80615e188d9b669c5938f3050e23e1c2db910526c65fb3e82c5743381c9295a8"
            "bc599bf76d9da8f4f6740e8d621426546490d79f5a24ca0f1894d81b817c1fdc989dcfd61eab6c79c6c136663d8aa7827dce04eb38"
            "168984adf51b4c72d8a0417df022c21b3b5f11917d9a0bbeb650745785793ccaa770bba8789e8025631c83eaf8beb6fa43b07bfcdc"
            "dceebdda2a2c6edad27f61d1441b631a7d6151b143d9e53230c753bd00ac41bc8e5bacb2deb575cbbcd85c889b27943e4be9a957cb"
            "8707ec51ee6b6bc877d1ceb5286146080ed0c0f51b81c48d125aed92d6987cab240a899fcfbcff78952c38d0d09a0364cf33dbe0b5"
            "aa6acd0cbab4c8bd7102392f16863b2c6ba09f74576d3599f35779abb3667116be78d9a188cec0e690ec");

        changed_accounts.insert(*from_hex("0x010001"));

        auto ta_data{ta_cursor.to_prefix({})};

        REQUIRE((ta_data.key.has_value() && ta_data.key.value() == *from_hex("0x00")));
        REQUIRE(ta_data.first_uncovered.has_value() == false);
        REQUIRE(ta_data.hash.has_value() == true);

        REQUIRE(collector.empty() == false);  // It MUST delete root node

        bool has_thrown{false};
        try {
            // Must throw as it can't find child 01
            (void)ta_cursor.to_next();
        } catch (...) {
            has_thrown = true;
        }
        REQUIRE(has_thrown);
    }

    SECTION("Root + 16 children with changes") {
        Collector collector{db_context.dir().path()};
        trie::PrefixSet changed_accounts{};
        PooledCursor trie_accounts(txn, table::kTrieOfAccounts);
        trie::TrieCursor ta_cursor{trie_accounts, &changed_accounts, &collector};

        // Fake root node with no hashes and only tree mask (must descend to all)
        Bytes k{};
        Bytes v{*from_hex(
            "ffff" /* all state bits set */
            "ffff" /* has all children */
            "0000" /* no hash mask */
            "061d711a452d9137600bc9a5fecb8fa8f4fe4496f232b0ec706c8fb601beff0b" /* root hash - must have it */)};

        trie_accounts.insert(to_slice(k), to_slice(v));

        // Generate 16 fake sub nodes - note root node above has all bits set in tree_mask
        v = *from_hex(
            "0001" /* at least one state bit */
            "0000" /* no tree mask */
            "0000" /* no hash mask */);

        for (uint8_t c{'\0'}; c < 0x10; ++c) {
            k.clear();
            k.push_back(c);
            trie_accounts.insert(to_slice(k), to_slice(v));
        }

        // Insert a change, so we don't get hash of root and
        // cursor forced to descend and traverse children
        changed_accounts.insert(*from_hex("0x000001"));

        // Moving to first MUST not throw
        REQUIRE_NOTHROW((void)ta_cursor.to_prefix({}));

        // Both root node and all child node should be traversed and deleted
        REQUIRE(collector.size() == 17);
    }

    SECTION("Empty prefixed trie no changes") {
        trie::PrefixSet changed_accounts{};
        PooledCursor trie_storage(txn, table::kTrieOfStorage);
        trie::TrieCursor ts_cursor{trie_storage, &changed_accounts};
        Bytes prefix{*from_hex("0xfff2bcbbf823e72a3a9025c14b96f5c28026735aeb7f19e5f2f317aa7a017c080000000000000001")};
        auto ts_data{ts_cursor.to_prefix(prefix)};

        REQUIRE(ts_data.key.has_value() == false);
        REQUIRE(ts_data.first_uncovered.has_value() == true);
        REQUIRE(ts_data.first_uncovered.value().empty() == true);
        REQUIRE(ts_data.hash.has_value() == false);

        bool has_thrown{false};
        try {
            // Must throw as we're at the end of tree
            ts_data = ts_cursor.to_next();
        } catch (...) {
            has_thrown = true;
        }

        REQUIRE(has_thrown);
    }

    SECTION("Missing prefixed root no changes") {
        trie::PrefixSet changed_storage{};
        PooledCursor trie_storage(txn, table::kTrieOfStorage);

        Bytes k{
            *from_hex("0xfff2bcbbf823e72a3a9025c14b96f5c28026735aeb7f19e5f2f317aa7a017c080000000000000001" /* prefix */
                      "00" /* first subnode */)};
        Bytes v{
            *from_hex("ffff" /* all state bits set */
                      "ffff" /* has all children */
                      "0000" /* no hash mask */
                      )};

        trie_storage.insert(to_slice(k), to_slice(v));

        trie::TrieCursor ts_cursor{trie_storage, &changed_storage};
        Bytes prefix{*from_hex("0xfff2bcbbf823e72a3a9025c14b96f5c28026735aeb7f19e5f2f317aa7a017c080000000000000001")};
        auto ts_data{ts_cursor.to_prefix(prefix)};

        REQUIRE(ts_data.key.has_value() == false);
        REQUIRE(ts_data.first_uncovered.has_value() == true);
        REQUIRE(ts_data.first_uncovered.value().empty() == true);
        REQUIRE(ts_data.hash.has_value() == false);

        bool has_thrown{false};
        try {
            // Must throw as we're at the end of tree
            ts_data = ts_cursor.to_next();
        } catch (...) {
            has_thrown = true;
        }

        REQUIRE(has_thrown);
    }
}

TEST_CASE("Trie Cursor Increment Nibbles") {
    // Incrementable same level
    Bytes input{*from_hex("0x010203")};
    std::optional<Bytes> incremented{trie::TrieCursor::increment_nibbled_key(input)};
    REQUIRE(incremented.has_value());
    REQUIRE(to_hex(*incremented, true) == "0x010204");

    // Incrementable up one level
    input = *from_hex("0x01020f");
    incremented = trie::TrieCursor::increment_nibbled_key(input);
    REQUIRE(incremented.has_value());
    REQUIRE(to_hex(*incremented, true) == "0x0103");

    // Increment overflows
    input = *from_hex("0x0f0f0f");
    incremented = trie::TrieCursor::increment_nibbled_key(input);
    REQUIRE(incremented.has_value() == false);

    // Increment empty
    input = Bytes{};
    incremented = trie::TrieCursor::increment_nibbled_key(input);
    REQUIRE(incremented.has_value() == false);
}

TEST_CASE("Trie Cursor KeyIsBefore") {
    ByteView input1_view{};
    ByteView input2_view{};

    REQUIRE(trie::TrieCursor::key_is_before(input1_view, input2_view) == false);

    Bytes input1{*from_hex("0x01")};
    Bytes input2{*from_hex("0x02")};
    input1_view = ByteView(input1.data(), input1.size());
    REQUIRE(trie::TrieCursor::key_is_before(input1_view, input2_view) == true);

    input2_view = ByteView(input2.data(), input2.size());
    REQUIRE(trie::TrieCursor::key_is_before(input1_view, input2_view) == true);
    REQUIRE(trie::TrieCursor::key_is_before(input2_view, input1_view) == false);
}

static evmc::bytes32 setup_storage(mdbx::txn& txn, ByteView storage_key) {
    const std::vector<std::pair<evmc::bytes32, Bytes>> locations{
        {0x1200000000000000000000000000000000000000000000000000000000000000_bytes32, *from_hex("0x42")},
        {0x1400000000000000000000000000000000000000000000000000000000000000_bytes32, *from_hex("0x01")},
        {0x3000000000000000000000000000000000000000000000000000000000E00000_bytes32, *from_hex("0x127a89")},
        {0x3000000000000000000000000000000000000000000000000000000000E00001_bytes32, *from_hex("0x05")},
    };

    PooledCursor hashed_storage(txn, table::kHashedStorage);
    HashBuilder storage_hb;
    Bytes value_rlp{};

    for (const auto& [location, value] : locations) {
        upsert_storage_value(hashed_storage, storage_key, location.bytes, value);
        value_rlp.clear();
        rlp::encode(value_rlp, value);
        storage_hb.add_leaf(unpack_nibbles(location.bytes), value_rlp);
    }

    return storage_hb.root_hash();
}

static std::map<Bytes, Node> read_all_nodes(ROCursor& cursor) {
    cursor.to_first(/*throw_notfound=*/false);
    std::map<Bytes, Node> out;
    auto save_nodes{[&out](ByteView key, ByteView value) {
        Node node;
        REQUIRE(Node::decode_from_storage(value, node));
        out.emplace(key, node);
    }};
    cursor_for_each(cursor, save_nodes);
    return out;
}

static Bytes nibbles_from_hex(std::string_view s) {
    Bytes unpacked(s.size(), '\0');
    for (size_t i{0}; i < s.size(); ++i) {
        unpacked[i] = *decode_hex_digit(s[i]);
    }
    return unpacked;
}

static evmc::bytes32 increment_intermediate_hashes(ROTxn& txn, const std::filesystem::path& etl_path,
                                                   PrefixSet* account_changes, PrefixSet* storage_changes) {
    Collector account_trie_node_collector{etl_path};
    Collector storage_trie_node_collector{etl_path};

    TrieLoader trie_loader(txn, account_changes, storage_changes, &account_trie_node_collector,
                           &storage_trie_node_collector);

    auto computed_root{trie_loader.calculate_root()};

    // Save collected node changes
    PooledCursor account_cursor(txn, table::kTrieOfAccounts);
    MDBX_put_flags_t flags{account_cursor.empty() ? MDBX_put_flags_t::MDBX_APPEND : MDBX_put_flags_t::MDBX_UPSERT};
    account_trie_node_collector.load(account_cursor, nullptr, flags);

    PooledCursor storage_cursor(txn, table::kTrieOfStorage);
    flags = storage_cursor.empty() ? MDBX_put_flags_t::MDBX_APPEND : MDBX_put_flags_t::MDBX_UPSERT;
    storage_trie_node_collector.load(storage_cursor, nullptr, flags);

    return computed_root;
}

static evmc::bytes32 regenerate_intermediate_hashes(ROTxn& txn, const std::filesystem::path& etl_path) {
    return increment_intermediate_hashes(txn, etl_path, nullptr, nullptr);
}

TEST_CASE("Account and storage trie") {
    test_util::TempChainData context;
    auto& txn{context.rw_txn()};

    // ----------------------------------------------------------------
    // Set up test accounts according to the example
    // in the big comment in intermediate_hashes.hpp
    // ----------------------------------------------------------------

    auto hashed_accounts{open_cursor(txn, table::kHashedAccounts)};

    HashBuilder hb;

    const evmc::bytes32 key1{0xB000000000000000000000000000000000000000000000000000000000000000_bytes32};
    const AccountEncodable a1{0, 3 * kEther};
    hashed_accounts.upsert(to_slice(key1), to_slice(a1.encode_for_storage()));
    hb.add_leaf(unpack_nibbles(key1.bytes), a1.rlp(/*storage_root=*/kEmptyRoot));

    // Some address whose hash starts with 0xB040
    const evmc::address address2{0x7db3e81b72d2695e19764583f6d219dbee0f35ca_address};
    const auto key2{keccak256(address2)};
    REQUIRE((key2.bytes[0] == 0xB0 && key2.bytes[1] == 0x40));
    const AccountEncodable a2{0, 1 * kEther};
    hashed_accounts.upsert(to_slice(key2.bytes), to_slice(a2.encode_for_storage()));
    hb.add_leaf(unpack_nibbles(key2.bytes), a2.rlp(/*storage_root=*/kEmptyRoot));

    // Some address whose hash starts with 0xB041
    const evmc::address address3{0x16b07afd1c635f77172e842a000ead9a2a222459_address};
    const auto key3{keccak256(address3)};
    REQUIRE((key3.bytes[0] == 0xB0 && key3.bytes[1] == 0x41));
    const evmc::bytes32 code_hash{0x5be74cad16203c4905c068b012a2e9fb6d19d036c410f16fd177f337541440dd_bytes32};
    const AccountEncodable a3{0, 2 * kEther, code_hash, kDefaultIncarnation};
    hashed_accounts.upsert(to_slice(key3.bytes), to_slice(a3.encode_for_storage()));

    Bytes storage_key{storage_prefix(key3.bytes, kDefaultIncarnation)};
    const evmc::bytes32 storage_root{setup_storage(txn, storage_key)};

    hb.add_leaf(unpack_nibbles(key3.bytes), a3.rlp(storage_root));

    const evmc::bytes32 key4a{0xB1A0000000000000000000000000000000000000000000000000000000000000_bytes32};
    const AccountEncodable a4a{0, 4 * kEther};
    hashed_accounts.upsert(to_slice(key4a), to_slice(a4a.encode_for_storage()));
    hb.add_leaf(unpack_nibbles(key4a.bytes), a4a.rlp(/*storage_root=*/kEmptyRoot));

    const evmc::bytes32 key5{0xB310000000000000000000000000000000000000000000000000000000000000_bytes32};
    const AccountEncodable a5{0, 8 * kEther};
    hashed_accounts.upsert(to_slice(key5), to_slice(a5.encode_for_storage()));
    hb.add_leaf(unpack_nibbles(key5.bytes), a5.rlp(/*storage_root=*/kEmptyRoot));

    const evmc::bytes32 key6{0xB340000000000000000000000000000000000000000000000000000000000000_bytes32};
    const AccountEncodable a6{0, 1 * kEther};
    hashed_accounts.upsert(to_slice(key6), to_slice(a6.encode_for_storage()));
    hb.add_leaf(unpack_nibbles(key6.bytes), a6.rlp(/*storage_root=*/kEmptyRoot));

    // ----------------------------------------------------------------
    // Populate account & storage trie DB tables
    // ----------------------------------------------------------------

    evmc::bytes32 expected_root{hb.root_hash()};
    evmc::bytes32 computed_root{regenerate_intermediate_hashes(txn, context.dir().temp().path())};
    REQUIRE(to_hex(computed_root.bytes, true) == to_hex(expected_root.bytes, true));

    // ----------------------------------------------------------------
    // Check account trie
    // ----------------------------------------------------------------

    PooledCursor account_trie(txn, table::kTrieOfAccounts);
    REQUIRE(account_trie.size() == 2);

    std::map<Bytes, Node> node_map{read_all_nodes(account_trie)};
    REQUIRE(node_map.size() == account_trie.size());

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

    PooledCursor storage_trie(txn, table::kTrieOfStorage);
    REQUIRE(storage_trie.size() == 1);

    node_map = read_all_nodes(storage_trie);
    CHECK(node_map.size() == storage_trie.size());

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
    const evmc::address address4b{0x4f61f2d5ebd991b85aa1677db97307caf5215c91_address};
    const auto key4b{keccak256(address4b)};
    REQUIRE(key4b.bytes[0] == key4a.bytes[0]);

    const AccountEncodable a4b{0, 5 * kEther};
    hashed_accounts.upsert(to_slice(key4b.bytes), to_slice(a4b.encode_for_storage()));

    PrefixSet account_changes{};
    PrefixSet storage_changes{};
    account_changes.insert(unpack_nibbles(Bytes(&key4b.bytes[0], kHashLength)));

    expected_root = 0x8e263cd4eefb0c3cbbb14e5541a66a755cad25bcfab1e10dd9d706263e811b28_bytes32;
    computed_root = increment_intermediate_hashes(txn, context.dir().temp().path(), &account_changes, &storage_changes);
    REQUIRE(to_hex(computed_root.bytes, true) == to_hex(expected_root.bytes, true));

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
        account_changes.clear();
        storage_changes.clear();

        hashed_accounts.erase(to_slice(key2.bytes));
        account_changes.insert(unpack_nibbles(Bytes(&key2.bytes[0], kHashLength)));
        expected_root = 0x986b623eac8b26c8624cbaffaa60c1b48a7b88be1574bd98bd88391fc34c0a9c_bytes32;

        {
            Collector account_trie_node_collector{context.dir().temp().path()};
            Collector storage_trie_node_collector{context.dir().temp().path()};
            TrieLoader trie_loader(txn, &account_changes, &storage_changes, &account_trie_node_collector,
                                   &storage_trie_node_collector);
            computed_root = trie_loader.calculate_root();
            REQUIRE(computed_root == expected_root);

            // Save collected node changes
            PooledCursor target(txn, table::kTrieOfAccounts);
            MDBX_put_flags_t flags{target.empty() ? MDBX_put_flags_t::MDBX_APPEND : MDBX_put_flags_t::MDBX_UPSERT};
            account_trie_node_collector.load(target, nullptr, flags);

            target.bind(txn, table::kTrieOfStorage);
            flags = target.empty() ? MDBX_put_flags_t::MDBX_APPEND : MDBX_put_flags_t::MDBX_UPSERT;
            storage_trie_node_collector.load(target, nullptr, flags);
        }

        node_map = read_all_nodes(account_trie);

        // Compared to previous case the node 0b40 has been deleted so nodes are 3-1 == 2
        CHECK(node_map.size() == 2);

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
        account_changes.clear();
        storage_changes.clear();

        hashed_accounts.erase(to_slice(key2.bytes));
        account_changes.insert(unpack_nibbles(Bytes(&key2.bytes[0], kHashLength)));

        hashed_accounts.erase(to_slice(key3.bytes));
        account_changes.insert(unpack_nibbles(Bytes(&key3.bytes[0], kHashLength)));

        expected_root = 0xaa953dc994f3375a95f2c413ed5a1a5a2f84d34b377d7587e3aa8dba944c12bf_bytes32;
        computed_root =
            increment_intermediate_hashes(txn, context.dir().temp().path(), &account_changes, &storage_changes);
        REQUIRE(computed_root == expected_root);

        node_map = read_all_nodes(account_trie);
        CHECK(node_map.size() == 2);

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
    const AccountEncodable account_one_ether{0, 1 * kEther};

    const std::vector<evmc::bytes32> keys{
        0x30af561000000000000000000000000000000000000000000000000000000000_bytes32,
        0x30af569000000000000000000000000000000000000000000000000000000000_bytes32,
        0x30af650000000000000000000000000000000000000000000000000000000000_bytes32,
        0x30af6f0000000000000000000000000000000000000000000000000000000000_bytes32,
        0x30af8f0000000000000000000000000000000000000000000000000000000000_bytes32,
        0x3100000000000000000000000000000000000000000000000000000000000000_bytes32,
    };

    test_util::TempChainData context;
    auto& txn{context.rw_txn()};

    auto hashed_accounts{open_cursor(txn, table::kHashedAccounts)};
    HashBuilder hb;

    for (const auto& key : keys) {
        hashed_accounts.upsert(to_slice(key), to_slice(account_one_ether.encode_for_storage()));
        hb.add_leaf(unpack_nibbles(key.bytes), account_one_ether.rlp(/*storage_root=*/kEmptyRoot));
    }

    const evmc::bytes32 expected_root{hb.root_hash()};
    const evmc::bytes32 computed_root{regenerate_intermediate_hashes(txn, context.dir().temp().path())};
    REQUIRE(to_hex(computed_root.bytes, true) == to_hex(expected_root.bytes, true));

    PooledCursor account_trie(txn, table::kTrieOfAccounts);
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
    return bytes_to_address(be);
}

static evmc::bytes32 int_to_bytes32(uint64_t i) {
    uint8_t be[8];
    endian::store_big_u64(be, i);
    return to_bytes32(be);
}

TEST_CASE("Trie Accounts : incremental vs regeneration") {
    test_util::TempChainData context;
    auto& txn{context.rw_txn()};

    PrefixSet account_changes;
    PrefixSet storage_changes;

    const size_t n{10'000};

    PooledCursor hashed_accounts{txn, table::kHashedAccounts};
    PooledCursor account_trie{txn, table::kTrieOfAccounts};

    // ------------------------------------------------------------------------------
    // Take A: create some accounts at genesis and then apply some changes
    // ------------------------------------------------------------------------------

    // Start with 3n accounts at genesis, each holding 1 ETH
    const AccountEncodable one_eth{0, 1 * kEther};
    for (size_t i{0}, e{3 * n}; i < e; ++i) {
        const evmc::address address{int_to_address(i)};
        const auto hash{keccak256(address)};
        hashed_accounts.upsert(to_slice(hash.bytes), to_slice(one_eth.encode_for_storage()));
    }

    // This populates TrieAccounts for the first pass
    (void)regenerate_intermediate_hashes(txn, context.dir().temp().path());

    // Double the balance of the first third of the accounts
    const AccountEncodable two_eth{0, 2 * kEther};
    for (size_t i{0}; i < n; ++i) {
        const evmc::address address{int_to_address(i)};
        const auto hash{keccak256(address)};
        hashed_accounts.upsert(to_slice(hash.bytes), to_slice(two_eth.encode_for_storage()));
        account_changes.insert(unpack_nibbles(Bytes(&hash.bytes[0], kHashLength)));
    }

    // Delete the second third of the accounts
    for (size_t i{n}, e{2 * n}; i < e; ++i) {
        const evmc::address address{int_to_address(i)};
        const auto hash{keccak256(address)};
        hashed_accounts.erase(to_slice(hash.bytes));
        account_changes.insert(unpack_nibbles(Bytes(&hash.bytes[0], kHashLength)));
    }

    // Don't touch the last third of genesis accounts

    // And add some new accounts, each holding 1 ETH
    for (size_t i{3 * n}, e{4 * n}; i < e; ++i) {
        const evmc::address address{int_to_address(i)};
        const auto hash{keccak256(address)};
        hashed_accounts.upsert(to_slice(hash.bytes), to_slice(one_eth.encode_for_storage()));
        account_changes.insert(unpack_nibbles(Bytes(&hash.bytes[0], kHashLength)), /* mark as created */ true);
    }

    const auto incremental_root{
        increment_intermediate_hashes(txn, context.dir().temp().path(), &account_changes, &storage_changes)};

    const std::map<Bytes, Node> incremental_nodes{read_all_nodes(account_trie)};

    // ------------------------------------------------------------------------------
    // Take B: generate intermediate hashes for the accounts as of Block 1 in one go,
    // without increment_intermediate_hashes
    // ------------------------------------------------------------------------------
    txn->clear_map(open_map(txn, table::kHashedAccounts));

    // Accounts [0,n) now hold 2 ETH
    for (size_t i{0}; i < n; ++i) {
        const evmc::address address{int_to_address(i)};
        const auto hash{keccak256(address)};
        hashed_accounts.upsert(to_slice(hash.bytes), to_slice(two_eth.encode_for_storage()));
    }

    // Accounts [n,2n) are deleted

    // Accounts [2n,4n) hold 1 ETH
    for (size_t i{2 * n}, e{4 * n}; i < e; ++i) {
        const evmc::address address{int_to_address(i)};
        const auto hash{keccak256(address)};
        hashed_accounts.upsert(to_slice(hash.bytes), to_slice(one_eth.encode_for_storage()));
    }

    txn->clear_map(open_map(txn, table::kTrieOfAccounts));
    txn->clear_map(open_map(txn, table::kTrieOfStorage));
    const auto fused_root{regenerate_intermediate_hashes(txn, context.dir().temp().path())};

    const std::map<Bytes, Node> fused_nodes{read_all_nodes(account_trie)};

    // ------------------------------------------------------------------------------
    // A and B should yield the same result
    // ------------------------------------------------------------------------------
    REQUIRE(to_hex(fused_root.bytes, true) == to_hex(incremental_root.bytes, true));
    REQUIRE(fused_nodes == incremental_nodes);
}

TEST_CASE("Trie Storage : incremental vs regeneration") {
    test_util::TempChainData context;
    auto& txn{context.rw_txn()};

    PrefixSet account_changes;
    PrefixSet storage_changes;

    const size_t n{2'000};

    PooledCursor hashed_accounts{txn, table::kHashedAccounts};
    PooledCursor hashed_storage{txn, table::kHashedStorage};
    PooledCursor storage_trie{txn, table::kTrieOfStorage};

    const uint64_t incarnation1{3};
    const uint64_t incarnation2{1};

    const AccountEncodable account1{
        5,                                                                           // nonce
        7 * kEther,                                                                  // balance
        0x5e3c5ae99a1c6785210d0d233641562557ad763e18907cca3a8d42bd0a0b4ecb_bytes32,  // code_hash
        incarnation1,                                                                // incarnation
    };

    const AccountEncodable account2{
        1,                                                                           // nonce
        13 * kEther,                                                                 // balance
        0x3a9c1d84e48734ae951e023197bda6d03933a4ca44124a2a544e227aa93efe75_bytes32,  // code_hash
        incarnation2,                                                                // incarnation
    };

    const evmc::address address1{0x1000000000000000000000000000000000000000_address};
    const evmc::address address2{0x2000000000000000000000000000000000000000_address};

    const auto hashed_address1{keccak256(address1)};
    const auto hashed_address2{keccak256(address2)};

    hashed_accounts.upsert(to_slice(hashed_address1.bytes), to_slice(account1.encode_for_storage()));
    hashed_accounts.upsert(to_slice(hashed_address2.bytes), to_slice(account2.encode_for_storage()));

    const Bytes storage_prefix1{storage_prefix(hashed_address1.bytes, incarnation1)};
    const Bytes storage_prefix2{storage_prefix(hashed_address2.bytes, incarnation2)};

    const auto upsert_storage_for_two_test_accounts = [&](size_t i, ByteView value, bool register_change,
                                                          bool new_records = false) {
        const evmc::bytes32 plain_loc1{int_to_bytes32(2 * i)};
        const evmc::bytes32 plain_loc2{int_to_bytes32(2 * i + 1)};

        const auto hashed_loc1{silkworm::keccak256(plain_loc1.bytes)};
        const auto hashed_loc2{silkworm::keccak256(plain_loc2.bytes)};

        const auto nibbled_hashed_loc1{unpack_nibbles(hashed_loc1.bytes)};
        const auto nibbled_hashed_loc2{unpack_nibbles(hashed_loc2.bytes)};

        upsert_storage_value(hashed_storage, storage_prefix1, hashed_loc1.bytes, value);
        upsert_storage_value(hashed_storage, storage_prefix2, hashed_loc2.bytes, value);
        if (register_change) {
            storage_changes.insert(Bytes{storage_prefix1 + nibbled_hashed_loc1}, new_records);
            storage_changes.insert(Bytes{storage_prefix2 + nibbled_hashed_loc2}, new_records);
        }
    };

    // ------------------------------------------------------------------------------
    // Take A: create some storage at genesis and then apply some changes at Block 1
    // ------------------------------------------------------------------------------

    // Start with 3n storage slots per account at genesis, each with the same value
    const Bytes value_x{*from_hex("42")};
    for (size_t i{0}, e{3 * n}; i < e; ++i) {
        upsert_storage_for_two_test_accounts(i, value_x, false);
    }

    (void)regenerate_intermediate_hashes(txn, context.dir().temp().path());

    // Change the value of the first third of the storage
    const Bytes value_y{*from_hex("71f602b294119bf452f1923814f5c6de768221254d3056b1bd63e72dc3142a29")};
    for (size_t i{0}; i < n; ++i) {
        upsert_storage_for_two_test_accounts(i, value_y, true);
    }

    // Delete the second third of the storage
    for (size_t i{n}, e{2 * n}; i < e; ++i) {
        upsert_storage_for_two_test_accounts(i, {}, true);
    }

    // Don't touch the last third of genesis storage

    // And add some new storage
    for (size_t i{3 * n}, e{4 * n}; i < e; ++i) {
        upsert_storage_for_two_test_accounts(i, value_x, true, true);
    }

    account_changes.insert(unpack_nibbles(hashed_address1.bytes));
    account_changes.insert(unpack_nibbles(hashed_address2.bytes));

    const auto incremental_root{
        increment_intermediate_hashes(txn, context.dir().temp().path(), &account_changes, &storage_changes)};

    const std::map<Bytes, Node> incremental_nodes{read_all_nodes(storage_trie)};

    // ------------------------------------------------------------------------------
    // Take B: generate intermediate hashes for the storage as of Block 1 in one go,
    // without increment_intermediate_hashes
    // ------------------------------------------------------------------------------
    txn->clear_map(open_map(txn, table::kHashedStorage));

    // The first third of the storage now has value_y
    for (size_t i{0}; i < n; ++i) {
        upsert_storage_for_two_test_accounts(i, value_y, false);
    }

    // The second third of the storage is deleted

    // The last third and the extra storage has value_x
    for (size_t i{2 * n}, e{4 * n}; i < e; ++i) {
        upsert_storage_for_two_test_accounts(i, value_x, false);
    }

    txn->clear_map(open_map(txn, table::kTrieOfAccounts));
    txn->clear_map(open_map(txn, table::kTrieOfStorage));
    const auto fused_root{regenerate_intermediate_hashes(txn, context.dir().temp().path())};

    const std::map<Bytes, Node> fused_nodes{read_all_nodes(storage_trie)};

    // ------------------------------------------------------------------------------
    // A and B should yield the same result
    // ------------------------------------------------------------------------------
    REQUIRE(to_hex(fused_root.bytes, true) == to_hex(incremental_root.bytes, true));
    REQUIRE(fused_nodes == incremental_nodes);
}

}  // namespace silkworm::trie
