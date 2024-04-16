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

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/types/block.hpp>

#include "snapshot_word_serializer.hpp"

namespace silkworm::snapshots {

void decode_word_into_header(ByteView word, BlockHeader& header);
void check_sanity_of_header_with_metadata(const BlockHeader& header, BlockNum block_from, BlockNum block_to);

struct HeaderSnapshotWordSerializer : public SnapshotWordSerializer {
    BlockHeader value;

    ~HeaderSnapshotWordSerializer() override = default;

    void decode_word(ByteView word) override {
        decode_word_into_header(word, value);
    }

    void check_sanity_with_metadata(BlockNum block_from, BlockNum block_to) override {
        check_sanity_of_header_with_metadata(value, block_from, block_to);
    }
};

}  // namespace silkworm::snapshots
