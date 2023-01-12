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

#include <silkworm/common/log.hpp>
#include <silkworm/common/util.hpp>
#include <silkworm/test/snapshot_files.hpp>

namespace silkworm {

using RecSplit8 = succinct::RecSplit8;

void Index::build() {
    SILK_TRACE << "Index::build path: " << segment_path_.path().string() << " start";

    Decompressor decoder{segment_path_.path()};
    decoder.open();

    const SnapshotFile index_file = segment_path_.index_file();
    RecSplit8 rec_split{decoder.words_count(), kBucketSize, index_file.path(), index_file.block_from()};

    SILK_INFO << "Build index for: " << segment_path_.path().string() << " start";
    uint64_t iterations{0};
    bool collision_detected{false};
    do {
        iterations++;
        SILK_INFO << "Process snapshot items to prepare index build for: " << segment_path_.path().string();
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
                word.clear();
            }
            return true;
        });
        if (!read_ok) throw std::runtime_error{"cannot build index for: " + segment_path_.path().string()};

        SILK_INFO << "Build RecSplit index for: " << segment_path_.path().string() << " [" << iterations << "]";
        collision_detected = rec_split.build();
        SILK_DEBUG << "Build RecSplit index collision_detected: " << collision_detected << " [" << iterations << "]";
        if (collision_detected) rec_split.reset_new_salt();
    } while (collision_detected);
    SILK_INFO << "Build index for: " << segment_path_.path().string() << " end [iterations=" << iterations << "]";

    SILK_TRACE << "Index::build path: " << segment_path_.path().string() << " end";
}

bool HeaderIndex::walk(RecSplit8& rec_split, uint64_t /*i*/, uint64_t offset, ByteView word) {
    const ByteView rlp_encoded_header{word.data() + 1, word.size() - 1};
    const ethash::hash256 hash = keccak256(rlp_encoded_header);
    rec_split.add_key(hash.bytes, kHashLength, offset);
    return true;
}

bool BodyIndex::walk(RecSplit8& rec_split, uint64_t i, uint64_t offset, ByteView /*word*/) {
    const auto size = test::encode_varint<uint64_t>(i, uint64_buffer_);
    rec_split.add_key(uint64_buffer_.data(), size, offset);
    uint64_buffer_.clear();
    return true;
}

bool TransactionIndex::walk(RecSplit8& /*rec_split*/, uint64_t /*i*/, uint64_t /*offset*/, ByteView /*word*/) {
    return true;
}

}  // namespace silkworm
