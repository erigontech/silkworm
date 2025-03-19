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

#include "header_segment.hpp"

#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/infra/common/ensure.hpp>

#include "../step_block_num_converter.hpp"

namespace silkworm::snapshots {

void encode_word_from_header(Bytes& word, const BlockHeader& header) {
    auto hash = header.hash();
    word.push_back(hash.bytes[0]);

    rlp::encode(word, header);
}

void decode_word_into_header(ByteView word, BlockHeader& header) {
    // First byte in data is first byte of header hash.
    ensure(!word.empty(), [&]() { return "decode_word_into_header: first hash byte missing"; });

    // Skip hash first byte to obtain encoded header RLP data
    ByteView encoded_header{word.data() + 1, word.length() - 1};

    const auto decode_result = rlp::decode(encoded_header, header);
    success_or_throw(decode_result, "decode_word_into_header: rlp::decode error");
}

void check_sanity_of_header_with_metadata(const BlockHeader& header, datastore::StepRange step_range) {
    auto block_num_range = db::blocks::kStepToBlockNumConverter.timestamp_range_from_step_range(step_range);
    BlockNum block_from = block_num_range.start;
    BlockNum block_to = block_num_range.end;
    ensure((header.number >= block_from) && (header.number < block_to), [&]() {
        return "check_sanity_of_header_with_metadata: header.number=" + std::to_string(header.number) +
               " outside of range [" + std::to_string(block_from) + ", " + std::to_string(block_to) + ")";
    });
}

}  // namespace silkworm::snapshots
