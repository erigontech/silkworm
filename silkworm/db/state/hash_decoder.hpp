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

#include <algorithm>

#include <silkworm/core/types/hash.hpp>
#include <silkworm/db/datastore/snapshots/common/codec.hpp>

namespace silkworm::db::state {

struct HashSnapshotsDecoder : public snapshots::Decoder {
    Hash value;

    ~HashSnapshotsDecoder() override = default;

    void decode_word(ByteView word) override {
        if (word.size() < kHashLength)
            throw std::runtime_error{"HashSnapshotsDecoder failed to decode"};
        value = Hash{word};
    }
};

static_assert(snapshots::DecoderConcept<HashSnapshotsDecoder>);

}  // namespace silkworm::db::state
