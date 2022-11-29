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

#include "index.hpp"

#include <silkworm/common/assert.hpp>
#include <silkworm/common/util.hpp>

namespace silkworm {

void Index::build() {
    Decompressor decoder{segment_path_.path()};
    decoder.open();

    const SnapshotFile index_file = segment_path_.index_file();
    RecSplit8 rec_split{decoder.words_count(), kBucketSize, index_file.path(), index_file.block_from()};

    const bool read_ok = decoder.read_ahead([&](Decompressor::Iterator it) {
        Bytes word{};
        word.reserve(kPageSize);
        uint64_t i{0}, offset{0};
        while (it.has_next()) {
            uint64_t next_position = it.next(word);
            if (bool ok = walk(rec_split, i, offset, word); !ok) {
                return false;
            }
            ++i;
            offset = next_position;
        }
        return true;
    });
    if (!read_ok) throw std::runtime_error{"cannot build index for: " + segment_path_.path().string()};

    rec_split.build();
    // TODO(canepat) if build KO, generate new salt and retry
}

bool HeaderIndex::walk(RecSplit8& rec_split, uint64_t /*i*/, uint64_t offset, ByteView word) {
    const ByteView rlp_encoded_header{word.data() + 1, word.size() - 1};
    const ethash::hash256 hash = keccak256(rlp_encoded_header);
    rec_split.add_key(hash.bytes, kHashLength, offset);
    return true;
}

}  // namespace silkworm
