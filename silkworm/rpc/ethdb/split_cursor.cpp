/*
   Copyright 2023 The Silkworm Authors

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

#include "split_cursor.hpp"

namespace silkworm::rpc::ethdb {

SplitCursor::SplitCursor(Cursor& inner_cursor, ByteView key, uint64_t match_bits, uint64_t part1_end,
                         uint64_t part2_start, uint64_t part3_start)
    : inner_cursor_{inner_cursor},
      key_{key},
      part1_end_{part1_end},
      part2_start_{part2_start},
      part3_start_{part3_start},
      match_bytes_{(match_bits + 7) / 8} {
    uint8_t shift_bits = match_bits & 7;
    if (shift_bits != 0) {
        mask_ = static_cast<uint8_t>(0xff << (8 - shift_bits));
    } else {
        mask_ = 0xff;
    }

    first_bytes_ = key.substr(0, match_bytes_ - 1);
    if (match_bytes_ > 0) {
        last_bits_ = key[match_bytes_ - 1] & mask_;
    }
}

Task<SplittedKeyValue> SplitCursor::seek() {
    KeyValue kv = co_await inner_cursor_.seek(key_);
    co_return split_key_value(kv);
}

Task<SplittedKeyValue> SplitCursor::next() {
    KeyValue kv = co_await inner_cursor_.next();
    co_return split_key_value(kv);
}

bool SplitCursor::match_key(const ByteView& key) {
    if (key.empty()) {
        return false;
    }
    if (match_bytes_ == 0) {
        return true;
    }
    if (key.size() < match_bytes_) {
        return false;
    }
    if (first_bytes_ != key.substr(0, match_bytes_ - 1)) {
        return false;
    }
    return ((key[match_bytes_ - 1] & mask_) == last_bits_);
}

SplittedKeyValue SplitCursor::split_key_value(const KeyValue& kv) {
    const Bytes& key = kv.key;

    if (key.empty()) {
        return SplittedKeyValue{};
    }
    if (!match_key(key)) {
        return SplittedKeyValue{};
    }

    SplittedKeyValue skv{key.substr(0, part1_end_)};

    if (key.size() > part2_start_) {
        skv.key2 = kv.key.substr(part2_start_, part3_start_ - part2_start_);
    }
    if (key.size() > part3_start_) {
        skv.key3 = kv.key.substr(part3_start_);
    }

    skv.value = kv.value;

    return skv;
}

SplitCursorDupSort::SplitCursorDupSort(CursorDupSort& inner_cursor, ByteView key, ByteView subkey,
                                       uint64_t match_bits, uint64_t part1_end, uint64_t value_offset)
    : inner_cursor_{inner_cursor},
      key_{key},
      subkey_{subkey},
      part1_end_{part1_end},
      match_bytes_{(match_bits + 7) / 8},
      value_offset_{value_offset} {
    uint8_t shift_bits = match_bits & 7;
    if (shift_bits != 0) {
        mask_ = static_cast<uint8_t>(0xff << (8 - shift_bits));
    } else {
        mask_ = 0xff;
    }

    first_bytes_ = key.substr(0, match_bytes_ - 1);
    if (match_bytes_ > 0) {
        last_bits_ = key[match_bytes_ - 1] & mask_;
    }
}

Task<SplittedKeyValue> SplitCursorDupSort::seek_both() {
    auto value = co_await inner_cursor_.seek_both(key_, subkey_);
    co_return split_key_value(KeyValue{key_, value});
}

Task<SplittedKeyValue> SplitCursorDupSort::next_dup() {
    KeyValue kv = co_await inner_cursor_.next_dup();
    co_return split_key_value(kv);
}

bool SplitCursorDupSort::match_key(const ByteView& key) {
    if (key.empty()) {
        return false;
    }
    if (match_bytes_ == 0) {
        return true;
    }
    if (key.size() < match_bytes_) {
        return false;
    }
    if (first_bytes_ != key.substr(0, match_bytes_ - 1)) {
        return false;
    }
    return ((key[match_bytes_ - 1] & mask_) == last_bits_);
}

SplittedKeyValue SplitCursorDupSort::split_key_value(const KeyValue& kv) {
    const Bytes& key = kv.key;

    if (key.empty()) {
        return SplittedKeyValue{};
    }
    if (!match_key(key)) {
        return SplittedKeyValue{};
    }

    SplittedKeyValue skv{};
    if (kv.value.size() >= value_offset_) {
        skv.key1 = key.substr(0, part1_end_);
        skv.key2 = kv.value.substr(0, value_offset_);
        skv.value = kv.value.substr(value_offset_);
    }

    return skv;
}

}  // namespace silkworm::rpc::ethdb
