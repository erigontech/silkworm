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

#include "huffman_code.hpp"

#include <catch2/catch_test_macros.hpp>

namespace silkworm::snapshots::seg {

TEST_CASE("huffman_code_table0") {
    std::vector<uint64_t> symbol_uses = {1, 2, 3};
    std::vector<HuffmanSymbolCode> expected_code_table = {
        {1, 2},
        {3, 2},
        {0, 1},
    };

    auto actual_code_table = huffman_code_table(symbol_uses);
    CHECK(actual_code_table == expected_code_table);
}

TEST_CASE("huffman_code_table1") {
    std::vector<uint64_t> symbol_uses = {
        1,
        11,
        11,
        11,
        11,
        11,
        11,
        11,
        11,
        11,
    };
    std::vector<HuffmanSymbolCode> expected_code_table = {
        {3, 4},
        {11, 4},
        {7, 4},
        {15, 4},
        {0, 3},
        {4, 3},
        {2, 3},
        {6, 3},
        {1, 3},
        {5, 3},
    };

    auto actual_code_table = huffman_code_table(symbol_uses);
    CHECK(actual_code_table == expected_code_table);
}

TEST_CASE("huffman_code_table2") {
    std::vector<uint64_t> symbol_uses = {
        9,
        10,
        90,
        90,
        101,
        200,
        400,
    };
    std::vector<HuffmanSymbolCode> expected_code_table = {
        {3, 5},
        {19, 5},
        {11, 4},
        {7, 4},
        {15, 4},
        {1, 2},
        {0, 1},
    };

    auto actual_code_table = huffman_code_table(symbol_uses);
    CHECK(actual_code_table == expected_code_table);
}

}  // namespace silkworm::snapshots::seg
