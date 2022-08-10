/*
   Copyright 2022 The Silkworm Authors

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

#include <catch2/catch.hpp>

#include <silkworm/common/test_context.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/etl/collector.hpp>
#include <silkworm/stagedsync/stage_interhashes/trie_cursor.hpp>
#include <silkworm/stagedsync/stage_interhashes/trie_loader.hpp>
#include <silkworm/trie/hash_builder.hpp>
#include <silkworm/trie/nibbles.hpp>
#include <silkworm/types/account.hpp>

namespace silkworm::trie {

TEST_CASE("Trie Cursor") {
    test::Context db_context{};
    auto txn{db_context.txn()};

    SECTION("Wrong prefix") {
        trie::PrefixSet changed_accounts{};
        db::Cursor trie_accounts(txn, db::table::kTrieOfAccounts);
        trie::TrieCursor ta_cursor{trie_accounts, &changed_accounts};

        Bytes prefix{*from_hex("0x010203")};
        bool has_thrown{false};
        bool has_thrown_argument{false};
        try {
            // Must throw as we're at the end of tree
            (void)ta_cursor.to_prefix(prefix);
        } catch (const std::invalid_argument&) {
            has_thrown = true;
            has_thrown_argument = true;
        } catch (...) {
            has_thrown = true;
        }

        REQUIRE(has_thrown);
        REQUIRE(has_thrown_argument);
    }

    SECTION("Empty trie no changes") {
        trie::PrefixSet changed_accounts{};
        db::Cursor trie_accounts(txn, db::table::kTrieOfAccounts);
        trie::TrieCursor ta_cursor{trie_accounts, &changed_accounts};
        auto ta_data{ta_cursor.to_prefix({})};

        REQUIRE(ta_data.skip_state == false);
        REQUIRE(ta_data.key.has_value() == false);
        REQUIRE(ta_data.first_uncovered.has_value() == true);
        REQUIRE(ta_data.hash.has_value() == false);

        bool has_thrown{false};
        try {
            // Must throw as we're at the end of tree
            ta_data = ta_cursor.to_next();
        } catch (...) {
            has_thrown = true;
        }

        REQUIRE(has_thrown);
    }

    SECTION("Only root trie no changes") {
        trie::PrefixSet changed_accounts{};
        db::Cursor trie_accounts(txn, db::table::kTrieOfAccounts);
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

        trie_accounts.insert(db::to_slice(k), db::to_slice(v));

        auto ta_data{ta_cursor.to_prefix({})};

        REQUIRE(ta_data.skip_state == true);
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

    SECTION("Malformed root trie - value len < 6") {
        trie::PrefixSet changed_accounts{};
        db::Cursor trie_accounts(txn, db::table::kTrieOfAccounts);
        trie::TrieCursor ta_cursor{trie_accounts, &changed_accounts};

        Bytes k{};
        Bytes v{*from_hex("0xff")};

        trie_accounts.insert(db::to_slice(k), db::to_slice(v));

        bool has_thrown{false};
        bool has_thrown_argument{false};
        try {
            // Must throw as node can't be loaded
            (void)ta_cursor.to_prefix({});
        } catch (const std::invalid_argument&) {
            has_thrown = true;
            has_thrown_argument = true;
        } catch (...) {
            has_thrown = true;
        }

        REQUIRE(has_thrown);
        REQUIRE(has_thrown_argument);
    }

    SECTION("Malformed root trie - value len >= 6 hashes len % kHashLength != 0") {
        trie::PrefixSet changed_accounts{};
        db::Cursor trie_accounts(txn, db::table::kTrieOfAccounts);
        trie::TrieCursor ta_cursor{trie_accounts, &changed_accounts};

        Bytes k{};
        Bytes v{*from_hex("0xffffffffffff0123456")};

        trie_accounts.insert(db::to_slice(k), db::to_slice(v));

        bool has_thrown{false};
        bool has_thrown_argument{false};
        try {
            // Must throw as node can't be loaded
            (void)ta_cursor.to_prefix({});
        } catch (const std::invalid_argument&) {
            has_thrown = true;
            has_thrown_argument = true;
        } catch (...) {
            has_thrown = true;
        }

        REQUIRE(has_thrown);
        REQUIRE(has_thrown_argument);
    }

    SECTION("Malformed root trie - no state mask") {
        trie::PrefixSet changed_accounts{};
        db::Cursor trie_accounts(txn, db::table::kTrieOfAccounts);
        trie::TrieCursor ta_cursor{trie_accounts, &changed_accounts};

        Bytes k{};
        Bytes v{*from_hex("0x0000ffffffff")};

        trie_accounts.insert(db::to_slice(k), db::to_slice(v));

        bool has_thrown{false};
        bool has_thrown_argument{false};
        try {
            // Must throw as node can't be loaded
            (void)ta_cursor.to_prefix({});
        } catch (const std::invalid_argument&) {
            has_thrown = true;
            has_thrown_argument = true;
        } catch (...) {
            has_thrown = true;
        }

        REQUIRE(has_thrown);
        REQUIRE(has_thrown_argument);
    }

    SECTION("Malformed root trie - tree mask not subset of state mask") {
        trie::PrefixSet changed_accounts{};
        db::Cursor trie_accounts(txn, db::table::kTrieOfAccounts);
        trie::TrieCursor ta_cursor{trie_accounts, &changed_accounts};

        Bytes k{};
        Bytes v{
            *from_hex("0001" /* 0b0000000000000001 */
                      "0400" /* 0b0000010000000000 */
                      "0000" /* 0b0000000000000000 */)};

        trie_accounts.insert(db::to_slice(k), db::to_slice(v));

        bool has_thrown{false};
        bool has_thrown_argument{false};
        try {
            // Must throw as node can't be loaded
            (void)ta_cursor.to_prefix({});
        } catch (const std::invalid_argument&) {
            has_thrown = true;
            has_thrown_argument = true;
        } catch (...) {
            has_thrown = true;
        }

        REQUIRE(has_thrown);
        REQUIRE(has_thrown_argument);
    }

    SECTION("Malformed root trie - hash mask not subset of state mask") {
        trie::PrefixSet changed_accounts{};
        db::Cursor trie_accounts(txn, db::table::kTrieOfAccounts);
        trie::TrieCursor ta_cursor{trie_accounts, &changed_accounts};

        Bytes k{};
        Bytes v{
            *from_hex("0001" /* 0b0000000000000001 */
                      "0000" /* 0b0000000000000000 */
                      "0400" /* 0b0000010000000000 */
                      )};

        trie_accounts.insert(db::to_slice(k), db::to_slice(v));

        bool has_thrown{false};
        bool has_thrown_argument{false};
        try {
            // Must throw as node can't be loaded
            (void)ta_cursor.to_prefix({});
        } catch (const std::invalid_argument&) {
            has_thrown = true;
            has_thrown_argument = true;
        } catch (...) {
            has_thrown = true;
        }

        REQUIRE(has_thrown);
        REQUIRE(has_thrown_argument);
    }

    SECTION("Malformed root trie - more hashes than allowed") {
        trie::PrefixSet changed_accounts{};
        db::Cursor trie_accounts(txn, db::table::kTrieOfAccounts);
        trie::TrieCursor ta_cursor{trie_accounts, &changed_accounts};

        Bytes k{};
        Bytes v{
            *from_hex("0xffffffff0001"                                                   /* state/tree/hash masks */
                      "08a6097114f741d87630f06fd8f8ff6b11889389b1f65e2ac07cc239233c896a" /* hash 1 */
                      "08a6097114f741d87630f06fd8f8ff6b11889389b1f65e2ac07cc239233c896a" /* hash 2 */
                      "08a6097114f741d87630f06fd8f8ff6b11889389b1f65e2ac07cc239233c896a" /* hash 3 */
                      )};

        trie_accounts.insert(db::to_slice(k), db::to_slice(v));

        bool has_thrown{false};
        bool has_thrown_argument{false};
        try {
            // Must throw as node can't be loaded
            (void)ta_cursor.to_prefix({});
        } catch (const std::invalid_argument&) {
            has_thrown = true;
            has_thrown_argument = true;
        } catch (...) {
            has_thrown = true;
        }

        REQUIRE(has_thrown);
        REQUIRE(has_thrown_argument);
    }

    SECTION("Malformed root trie - no root hash") {
        trie::PrefixSet changed_accounts{};
        db::Cursor trie_accounts(txn, db::table::kTrieOfAccounts);
        trie::TrieCursor ta_cursor{trie_accounts, &changed_accounts};

        Bytes k{};
        Bytes v{
            *from_hex("0xffffffff0001"                                                   /* state/tree/hash masks */
                      "08a6097114f741d87630f06fd8f8ff6b11889389b1f65e2ac07cc239233c896a" /* hash 1 */
                      )};

        trie_accounts.insert(db::to_slice(k), db::to_slice(v));

        bool has_thrown{false};
        bool has_thrown_logic{false};
        try {
            // Must throw as node is loaded but being a root it does not have root hash
            (void)ta_cursor.to_prefix({});
        } catch (const std::logic_error&) {
            has_thrown = true;
            has_thrown_logic = true;
        } catch (...) {
            has_thrown = true;
        }

        REQUIRE(has_thrown);
        REQUIRE(has_thrown_logic);
    }

    SECTION("Only root trie with changes") {
        trie::PrefixSet changed_accounts{};
        db::Cursor trie_accounts(txn, db::table::kTrieOfAccounts);
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

        trie_accounts.insert(db::to_slice(k), db::to_slice(v));
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
        etl::Collector collector{db_context.dir().path()};
        trie::PrefixSet changed_accounts{};
        db::Cursor trie_accounts(txn, db::table::kTrieOfAccounts);
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
        trie_accounts.insert(db::to_slice(k), db::to_slice(v));

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

        REQUIRE(ta_data.skip_state == true);
        REQUIRE((ta_data.key.has_value() == true && ta_data.key.value() == *from_hex("0x00")));
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
        etl::Collector collector{db_context.dir().path()};
        trie::PrefixSet changed_accounts{};
        db::Cursor trie_accounts(txn, db::table::kTrieOfAccounts);
        trie::TrieCursor ta_cursor{trie_accounts, &changed_accounts, &collector};

        // Fake root node with no hashes and only tree mask (must descend to all)
        Bytes k{};
        Bytes v{*from_hex(
            "ffff" /* all state bits set */
            "ffff" /* has all children */
            "0000" /* no hash mask */
            "061d711a452d9137600bc9a5fecb8fa8f4fe4496f232b0ec706c8fb601beff0b" /* root hash - must have it */)};

        trie_accounts.insert(db::to_slice(k), db::to_slice(v));

        // Generate 16 fake sub nodes - note root node above has all bits set in tree_mask
        v = *from_hex(
            "0001" /* at least one state bit */
            "0000" /* no tree mask */
            "0000" /* no hash mask */);

        for (uint8_t c{'\0'}; c < 0x10; ++c) {
            k.clear();
            k.push_back(c);
            trie_accounts.insert(db::to_slice(k), db::to_slice(v));
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
        db::Cursor trie_storage(txn, db::table::kTrieOfStorage);
        trie::TrieCursor ts_cursor{trie_storage, &changed_accounts};
        Bytes prefix{*from_hex("0xfff2bcbbf823e72a3a9025c14b96f5c28026735aeb7f19e5f2f317aa7a017c080000000000000001")};
        auto ts_data{ts_cursor.to_prefix(prefix)};

        REQUIRE(ts_data.skip_state == false);
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
        db::Cursor trie_storage(txn, db::table::kTrieOfStorage);

        Bytes k{
            *from_hex("0xfff2bcbbf823e72a3a9025c14b96f5c28026735aeb7f19e5f2f317aa7a017c080000000000000001" /* prefix */
                      "00" /* first subnode */)};
        Bytes v{
            *from_hex("ffff" /* all state bits set */
                      "ffff" /* has all children */
                      "0000" /* no hash mask */
                      )};

        trie_storage.insert(db::to_slice(k), db::to_slice(v));

        trie::TrieCursor ts_cursor{trie_storage, &changed_storage};
        Bytes prefix{*from_hex("0xfff2bcbbf823e72a3a9025c14b96f5c28026735aeb7f19e5f2f317aa7a017c080000000000000001")};
        auto ts_data{ts_cursor.to_prefix(prefix)};

        REQUIRE(ts_data.skip_state == false);
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
    static const std::vector<std::pair<evmc::bytes32, Bytes>> locations{
        {0x1200000000000000000000000000000000000000000000000000000000000000_bytes32, *from_hex("0x42")},
        {0x1400000000000000000000000000000000000000000000000000000000000000_bytes32, *from_hex("0x01")},
        {0x3000000000000000000000000000000000000000000000000000000000E00000_bytes32, *from_hex("0x127a89")},
        {0x3000000000000000000000000000000000000000000000000000000000E00001_bytes32, *from_hex("0x05")},
    };

    db::Cursor hashed_storage(txn, db::table::kHashedStorage);
    HashBuilder storage_hb;
    Bytes value_rlp{};

    for (auto [location, value] : locations) {
        db::upsert_storage_value(hashed_storage, storage_key, location, value);
        value_rlp.clear();
        rlp::encode(value_rlp, value);
        storage_hb.add_leaf(unpack_nibbles(location), value_rlp);
    }

    return storage_hb.root_hash();
}

static std::map<Bytes, Node> read_all_nodes(mdbx::cursor& cursor) {
    cursor.to_first(/*throw_notfound=*/false);
    std::map<Bytes, Node> out;
    db::WalkFunc save_nodes{[&out](mdbx::cursor&, mdbx::cursor::move_result& entry) {
        const Node node{*Node::from_encoded_storage(db::from_slice(entry.value))};
        out.emplace(db::from_slice(entry.key), node);
        return true;
    }};
    db::cursor_for_each(cursor, save_nodes);
    return out;
}

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

static evmc::bytes32 increment_intermediate_hashes(mdbx::txn& txn, std::filesystem::path etl_path,
                                                   PrefixSet* account_changes, PrefixSet* storage_changes) {
    etl::Collector account_trie_node_collector{etl_path};
    etl::Collector storage_trie_node_collector{etl_path};

    TrieLoader trie_loader(txn, account_changes, storage_changes, &account_trie_node_collector,
                           &storage_trie_node_collector);

    auto computed_root{trie_loader.calculate_root()};

    // Save collected node changes
    db::Cursor target(txn, db::table::kTrieOfAccounts);
    MDBX_put_flags_t flags{target.size() ? MDBX_put_flags_t::MDBX_UPSERT : MDBX_put_flags_t::MDBX_APPEND};
    account_trie_node_collector.load(target, nullptr, flags);

    target.bind(txn, db::table::kTrieOfStorage);
    flags = target.empty() ? MDBX_put_flags_t::MDBX_APPEND : MDBX_put_flags_t::MDBX_UPSERT;
    storage_trie_node_collector.load(target, nullptr, flags);

    return computed_root;
}

static evmc::bytes32 regenerate_intermediate_hashes(mdbx::txn& txn, std::filesystem::path etl_path) {
    return increment_intermediate_hashes(txn, etl_path, nullptr, nullptr);
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

    evmc::bytes32 expected_root{hb.root_hash()};
    evmc::bytes32 computed_root{regenerate_intermediate_hashes(txn, context.dir().etl().path())};
    REQUIRE(computed_root == expected_root);

    // ----------------------------------------------------------------
    // Check account trie
    // ----------------------------------------------------------------

    db::Cursor account_trie(txn, db::table::kTrieOfAccounts);
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

    db::Cursor storage_trie(txn, db::table::kTrieOfStorage);
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
    const auto address4b{0x4f61f2d5ebd991b85aa1677db97307caf5215c91_address};
    const auto key4b{keccak256(address4b)};
    REQUIRE(key4b.bytes[0] == key4a.bytes[0]);

    const Account a4b{0, 5 * kEther};
    hashed_accounts.upsert(db::to_slice(key4b.bytes), db::to_slice(a4b.encode_for_storage()));

    PrefixSet account_changes{};
    PrefixSet storage_changes{};
    account_changes.insert(Bytes(&key4b.bytes[0], kHashLength));

    expected_root = 0x8e263cd4eefb0c3cbbb14e5541a66a755cad25bcfab1e10dd9d706263e811b28_bytes32;
    computed_root = increment_intermediate_hashes(txn, context.dir().etl().path(), &account_changes, &storage_changes);
    REQUIRE(expected_root == computed_root);

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

        hashed_accounts.erase(db::to_slice(key2.bytes));
        account_changes.insert(Bytes(&key2.bytes[0], kHashLength));
        expected_root = 0x986b623eac8b26c8624cbaffaa60c1b48a7b88be1574bd98bd88391fc34c0a9c_bytes32;

        {
            etl::Collector account_trie_node_collector{context.dir().etl().path()};
            etl::Collector storage_trie_node_collector{context.dir().etl().path()};
            TrieLoader trie_loader(txn, &account_changes, &storage_changes, &account_trie_node_collector,
                                   &storage_trie_node_collector);
            computed_root = trie_loader.calculate_root();
            REQUIRE(computed_root == expected_root);

            // Save collected node changes
            db::Cursor target(txn, db::table::kTrieOfAccounts);
            MDBX_put_flags_t flags{target.size() ? MDBX_put_flags_t::MDBX_UPSERT : MDBX_put_flags_t::MDBX_APPEND};
            account_trie_node_collector.load(target, nullptr, flags);

            target.bind(txn, db::table::kTrieOfStorage);
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

        hashed_accounts.erase(db::to_slice(key2.bytes));
        account_changes.insert(Bytes(&key2.bytes[0], kHashLength));

        hashed_accounts.erase(db::to_slice(key3.bytes));
        account_changes.insert(Bytes(&key3.bytes[0], kHashLength));

        expected_root = 0xaa953dc994f3375a95f2c413ed5a1a5a2f84d34b377d7587e3aa8dba944c12bf_bytes32;
        computed_root = increment_intermediate_hashes(txn, context.dir().etl().path(), &account_changes, &storage_changes);
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

}  // namespace silkworm::trie
