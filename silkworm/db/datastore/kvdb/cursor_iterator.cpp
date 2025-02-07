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

#include "cursor_iterator.hpp"

#include "raw_codec.hpp"

namespace silkworm::datastore::kvdb {

void CursorIterator::decode(const CursorResult& result) {
    if (result) {
        if (decoders_.first) {
            decoders_.first->decode(result.key);
        }
        if (decoders_.second) {
            decoders_.second->decode(result.value);
        }
    } else {
        decoders_.first.reset();
        decoders_.second.reset();
    }
}

bool operator==(const CursorIterator& lhs, const CursorIterator& rhs) {
    return (lhs.decoders_ == rhs.decoders_) &&
           ((!lhs.decoders_.first && !lhs.decoders_.second) || (lhs.cursor_ == rhs.cursor_));
}

static_assert(std::input_iterator<CursorMoveIterator>);
static_assert(std::input_iterator<CursorIterator>);
static_assert(std::input_iterator<CursorKVIterator<RawDecoder<Bytes>, RawDecoder<Bytes>>>);
static_assert(std::input_iterator<CursorKeysIterator<RawDecoder<Bytes>>>);
static_assert(std::input_iterator<CursorValuesIterator<RawDecoder<Bytes>>>);

}  // namespace silkworm::datastore::kvdb
