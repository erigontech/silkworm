// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <gmock/gmock.h>

#include <silkworm/db/kv/api/cursor.hpp>

namespace silkworm::db::test_util {

class MockCursor : public kv::api::Cursor {
  public:
    MOCK_METHOD((uint32_t), cursor_id, (), (const));
    MOCK_METHOD((Task<void>), open_cursor, (std::string_view table_name, bool is_dup_sorted));
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
    MOCK_METHOD((Task<void>), open_cursor, (std::string_view table_name, bool is_dup_sorted));
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
