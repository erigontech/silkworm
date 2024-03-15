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

#include "intermediate_compressed_stream.hpp"

#include <sstream>

#include <catch2/catch.hpp>

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
