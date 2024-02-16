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

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace silkworm::snapshots::seg {

struct HuffmanSymbolCode {
    //! Code of a symbol. Only the lowest code_bits are meaningful.
    uint64_t code{};
    //! The number bits in the symbol code, aka code length, aka depth in the Huffman tree.
    uint8_t code_bits{};

    friend bool operator==(const HuffmanSymbolCode&, const HuffmanSymbolCode&) = default;
};

/**
 * Builds a Huffman code table.
 * @param symbol_uses Sorted symbol usage frequencies.
 * @return Huffman codes of each symbol.
 */
std::vector<HuffmanSymbolCode> huffman_code_table(const std::vector<uint64_t>& symbol_uses);

/**
 * Produce an ordering of codes by code bits.
 * This is used as a Huffman table representation for serialization.
 * If only the symbol code lengths are stored in this order,
 * then the whole code table can be recovered.
 * @param codes Huffman codes of each symbol.
 * @return Reordered indexes of codes.
 */
std::vector<size_t> huffman_code_table_order_by_codes(
    const std::vector<HuffmanSymbolCode>& codes);

/**
 * Produce an ordering of codes by symbol frequency and code bits.
 * This is used to produce a stable order for the huffman_code_table input.
 * @param symbol_uses Symbol usage frequencies.
 * @param codes Temporary Huffman codes of each symbol.
 * @return Reordered indexes of codes.
 */
std::vector<size_t> huffman_code_table_order_by_uses_and_codes(
    const std::vector<uint64_t>& symbol_uses,
    const std::vector<uint64_t>& codes);

}  // namespace silkworm::snapshots::seg
