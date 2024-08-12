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

#include <gmock/gmock.h>

#include <silkworm/db/kv/api/cursor.hpp>

namespace silkworm::db::test_util {

class MockCursor : public kv::api::Cursor {
  public:
    MOCK_METHOD((uint32_t), cursor_id, (), (const));
    MOCK_METHOD((Task<void>), open_cursor, (const std::string& table_name, bool is_dup_sorted));
    MOCK_METHOD((Task<kv::api::KeyValue>), seek, (ByteView key));
    MOCK_METHOD((Task<kv::api::KeyValue>), seek_exact, (ByteView key));
    MOCK_METHOD((Task<kv::api::KeyValue>), first, ());
    MOCK_METHOD((Task<kv::api::KeyValue>), last, ());
    MOCK_METHOD((Task<kv::api::KeyValue>), next, ());
    MOCK_METHOD((Task<kv::api::KeyValue>), previous, ());
    MOCK_METHOD((Task<void>), close_cursor, ());
};

class MockCursorDupSort : public kv::api::CursorDupSort {
  public:
    MOCK_METHOD((uint32_t), cursor_id, (), (const));
    MOCK_METHOD((Task<void>), open_cursor, (const std::string& table_name, bool is_dup_sorted));
    MOCK_METHOD((Task<kv::api::KeyValue>), seek, (ByteView key));
    MOCK_METHOD((Task<kv::api::KeyValue>), seek_exact, (ByteView key));
    MOCK_METHOD((Task<kv::api::KeyValue>), first, ());
    MOCK_METHOD((Task<kv::api::KeyValue>), last, ());
    MOCK_METHOD((Task<kv::api::KeyValue>), next, ());
    MOCK_METHOD((Task<kv::api::KeyValue>), previous, ());
    MOCK_METHOD((Task<kv::api::KeyValue>), next_dup, ());
    MOCK_METHOD((Task<void>), close_cursor, ());
    MOCK_METHOD((Task<Bytes>), seek_both, (ByteView, ByteView));
    MOCK_METHOD((Task<kv::api::KeyValue>), seek_both_exact, (ByteView, ByteView));
};

}  // namespace silkworm::db::test_util
