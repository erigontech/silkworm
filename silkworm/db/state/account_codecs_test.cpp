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

#include "account_codecs.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/util.hpp>

namespace silkworm::db::state {

TEST_CASE("AccountKVDBCodec") {
    using evmc::literals::operator""_address;
    using datastore::kvdb::to_slice;
    AccountKVDBCodec codec;
    SECTION("encode") {
        CHECK(codec.encode() == to_slice(*from_hex("")));
        codec.value = std::nullopt;
        CHECK(codec.encode() == to_slice(*from_hex("")));
        codec.value = Account{};
        CHECK(codec.encode() == to_slice(*from_hex("00000000")));
        codec.value = {2, 3, kEmptyRoot, 4};
        CHECK(codec.encode() == to_slice(*from_hex("010201032056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4210104")));
        codec.value = {2, 3, kEmptyHash, 4};
        CHECK(codec.encode() == to_slice(*from_hex("01020103000104")));
        codec.value = {0, 3, kEmptyHash, 4};
        CHECK(codec.encode() == to_slice(*from_hex("000103000104")));
        codec.value = {2, 0, kEmptyHash, 4};
        CHECK(codec.encode() == to_slice(*from_hex("010200000104")));
        codec.value = {2, 3, kEmptyHash, 0};
        CHECK(codec.encode() == to_slice(*from_hex("010201030000")));
    }
    SECTION("decode") {
        codec.decode(to_slice(*from_hex("")));
        CHECK(!codec.value);
        codec.decode(to_slice(*from_hex("00000000")));
        CHECK(codec.value == Account{});
        codec.decode(to_slice(*from_hex("010201032056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4210104")));
        CHECK(codec.value == Account{2, 3, kEmptyRoot, 4});
        codec.decode(to_slice(*from_hex("01020103000104")));
        CHECK(codec.value == Account{2, 3, kEmptyHash, 4});
        codec.decode(to_slice(*from_hex("000103000104")));
        CHECK(codec.value == Account{0, 3, kEmptyHash, 4});
        codec.decode(to_slice(*from_hex("010200000104")));
        CHECK(codec.value == Account{2, 0, kEmptyHash, 4});
        codec.decode(to_slice(*from_hex("010201030000")));
        CHECK(codec.value == Account{2, 3, kEmptyHash, 0});
        codec.decode(to_slice(*from_hex("01020203e820f1885eda54b7a053318cd41e2093220dab15d65381b1157a3633a83bfd5c92390105")));
        CHECK(codec.value == Account{2, 1000, 0xf1885eda54b7a053318cd41e2093220dab15d65381b1157a3633a83bfd5c9239_bytes32, 5});
    }
}

TEST_CASE("AccountSnapshotsCodec") {
    using evmc::literals::operator""_address;
    AccountSnapshotsCodec codec;
    SECTION("encode") {
        CHECK(codec.encode_word() == *from_hex(""));
        codec.value = std::nullopt;
        CHECK(codec.encode_word() == *from_hex(""));
        codec.value = Account{};
        CHECK(codec.encode_word() == *from_hex("00000000"));
        codec.value = {2, 3, kEmptyRoot, 4};
        CHECK(codec.encode_word() == *from_hex("010201032056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4210104"));
        codec.value = {2, 3, kEmptyHash, 4};
        CHECK(codec.encode_word() == *from_hex("01020103000104"));
        codec.value = {0, 3, kEmptyHash, 4};
        CHECK(codec.encode_word() == *from_hex("000103000104"));
        codec.value = {2, 0, kEmptyHash, 4};
        CHECK(codec.encode_word() == *from_hex("010200000104"));
        codec.value = {2, 3, kEmptyHash, 0};
        CHECK(codec.encode_word() == *from_hex("010201030000"));
    }
    SECTION("decode") {
        using Word = snapshots::Decoder::Word;
        Word word1{*from_hex("")};
        codec.decode_word(word1);
        CHECK(!codec.value);
        Word word2{*from_hex("00000000")};
        codec.decode_word(word2);
        CHECK(codec.value == Account{});
        Word word3{*from_hex("010201032056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4210104")};
        codec.decode_word(word3);
        CHECK(codec.value == Account{2, 3, kEmptyRoot, 4});
        Word word4{*from_hex("01020103000104")};
        codec.decode_word(word4);
        CHECK(codec.value == Account{2, 3, kEmptyHash, 4});
        Word word5{*from_hex("000103000104")};
        codec.decode_word(word5);
        CHECK(codec.value == Account{0, 3, kEmptyHash, 4});
        Word word6{*from_hex("010200000104")};
        codec.decode_word(word6);
        CHECK(codec.value == Account{2, 0, kEmptyHash, 4});
        Word word7{*from_hex("010201030000")};
        codec.decode_word(word7);
        CHECK(codec.value == Account{2, 3, kEmptyHash, 0});
        Word word8{*from_hex("01020203e820f1885eda54b7a053318cd41e2093220dab15d65381b1157a3633a83bfd5c92390105")};
        codec.decode_word(word8);
        CHECK(codec.value == Account{2, 1000, 0xf1885eda54b7a053318cd41e2093220dab15d65381b1157a3633a83bfd5c9239_bytes32, 5});
    }
}

}  // namespace silkworm::db::state
