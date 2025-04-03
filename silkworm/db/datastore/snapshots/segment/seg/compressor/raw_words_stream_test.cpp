// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
