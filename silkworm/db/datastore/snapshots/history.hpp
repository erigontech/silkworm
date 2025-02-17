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

#include "history_accessor_index.hpp"
#include "inverted_index.hpp"
#include "rec_split/accessor_index.hpp"
#include "segment/segment_reader.hpp"
#include "segment_and_accessor_index.hpp"

namespace silkworm::snapshots {

struct History {
    const segment::SegmentFileReader& segment;
    const rec_split::AccessorIndex& accessor_index;
    InvertedIndex inverted_index;

    template <EncoderConcept TIIKeyEncoder>
    static HistoryAccessorIndexKeyEncoder<TIIKeyEncoder> make_accessor_index_key_encoder() {
        return HistoryAccessorIndexKeyEncoder<TIIKeyEncoder>{};
    }

    SegmentAndAccessorIndex segment_and_index() const {
        return {segment, accessor_index};
    }
};

}  // namespace silkworm::snapshots
