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

#include <string>

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/db/kv/api/cursor.hpp>
#include <silkworm/db/kv/api/endpoint/key_value.hpp>
#include <silkworm/rpc/common/util.hpp>

namespace silkworm::rpc::ethdb {

using db::kv::api::Cursor;
using db::kv::api::CursorDupSort;
using db::kv::api::KeyValue;

struct SplittedKeyValue {
    Bytes key1;
    Bytes key2;
    Bytes key3;
    Bytes value;
};

class SplitCursor {
  public:
    SplitCursor(Cursor& inner_cursor, ByteView key, uint64_t match_bits, uint64_t part1_end, uint64_t part2_start, uint64_t part3_start);
    SplitCursor& operator=(const SplitCursor&) = delete;

    Task<SplittedKeyValue> seek();

    Task<SplittedKeyValue> next();

  private:
    Cursor& inner_cursor_;
    Bytes key_;
    Bytes first_bytes_;
    uint8_t last_bits_;
    uint64_t part1_end_;
    uint64_t part2_start_;
    uint64_t part3_start_;
    uint64_t match_bytes_;
    uint8_t mask_;

    bool match_key(const ByteView& key);
    SplittedKeyValue split_key_value(const KeyValue& kv);
};

class SplitCursorDupSort {
  public:
    SplitCursorDupSort(CursorDupSort& inner_cursor, ByteView key, ByteView subkey, uint64_t match_bits, uint64_t part1_end, uint64_t value_offset);
    SplitCursorDupSort& operator=(const SplitCursorDupSort&) = delete;

    Task<SplittedKeyValue> seek_both();

    Task<SplittedKeyValue> next_dup();

  private:
    CursorDupSort& inner_cursor_;
    Bytes key_;
    Bytes subkey_;
    Bytes first_bytes_;
    uint8_t last_bits_;
    uint64_t part1_end_;
    uint64_t match_bytes_;
    uint8_t mask_;
    uint64_t value_offset_;

    bool match_key(const ByteView& key);
    SplittedKeyValue split_key_value(const KeyValue& kv);
};

}  // namespace silkworm::rpc::ethdb
