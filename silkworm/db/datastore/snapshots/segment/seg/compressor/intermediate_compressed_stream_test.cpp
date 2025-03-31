// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "intermediate_compressed_stream.hpp"

#include <sstream>

#include <catch2/catch_test_macros.hpp>

namespace silkworm::snapshots::seg {

using namespace std;

TEST_CASE("IntermediateCompressedStream") {
    stringstream stream;

    IntermediateCompressedStream::CompressedWord word1{
        .raw_length = 123,
        .pattern_positions = {
            {0, 1},
            {100, 2},
            {200, 1},
            {300, 3},
        },
    };
    Bytes word1_uncovered_data = {1, 2, 3};

    IntermediateCompressedStream::CompressedWord word2{
        .raw_length = 555,
        .pattern_positions = {
            {1000, 3},
            {2000, 2},
            {3000, 1},
        },
    };
    Bytes word2_uncovered_data(100, 42);

    IntermediateCompressedStream words_out{stream};
    words_out.write_word(word1);
    words_out.write_uncovered_data(word1_uncovered_data);
    words_out.write_word(word2);
    words_out.write_uncovered_data(word2_uncovered_data);

    IntermediateCompressedStream words_in{stream};
    CHECK(words_in.read_word() == word1);
    CHECK(words_in.read_uncovered_data(word1_uncovered_data.size()) == word1_uncovered_data);
    CHECK(words_in.read_word() == word2);
    CHECK(words_in.read_uncovered_data(word2_uncovered_data.size()) == word2_uncovered_data);
}

}  // namespace silkworm::snapshots::seg
