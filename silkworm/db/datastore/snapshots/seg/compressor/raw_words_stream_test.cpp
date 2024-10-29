/*
   Copyright 2024 The Silkworm Authors

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

#include "raw_words_stream.hpp"

#include <sstream>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/bytes_to_string.hpp>

namespace silkworm::snapshots::seg {

using namespace std;

static ByteView operator""_bv(const char* data, size_t size) {
    return string_view_to_byte_view({data, size});
}

TEST_CASE("RawWordsStream") {
    stringstream stream;

    RawWordsStream words_out{stream};
    words_out.write_word("hello"_bv);
    words_out.write_word("world"_bv, false);
    words_out.write_word("!!!"_bv);

    RawWordsStream words_in{stream};
    CHECK(words_in.read_word() == make_pair(Bytes("hello"_bv), true));
    CHECK(words_in.read_word() == make_pair(Bytes("world"_bv), false));
    CHECK(words_in.read_word() == make_pair(Bytes("!!!"_bv), true));
    CHECK(words_in.read_word() == nullopt);
}

}  // namespace silkworm::snapshots::seg
