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

namespace silkworm {
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

    SECTION("Only malformed root trie no changes") {
        trie::PrefixSet changed_accounts{};
        db::Cursor trie_accounts(txn, db::table::kTrieOfAccounts);
        trie::TrieCursor ta_cursor{trie_accounts, &changed_accounts};

        Bytes k{};
        Bytes v{*from_hex(
            "0xffffffffffffc587157345c796457244932c27c7"
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

        bool has_thrown{false};
        bool has_thrown_logic{false};
        try {
            // Must throw as we're at the end of tree
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

}  // namespace silkworm
