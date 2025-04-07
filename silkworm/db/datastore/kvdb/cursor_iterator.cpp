// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
