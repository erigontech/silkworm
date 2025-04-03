// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>
#include <string>

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/core/common/util.hpp>

#include "endpoint/key_value.hpp"

namespace silkworm::db::kv::api {

class Cursor {
  public:
    Cursor() = default;
    virtual ~Cursor() = default;

    Cursor(const Cursor&) = delete;
    Cursor& operator=(const Cursor&) = delete;

    virtual uint32_t cursor_id() const = 0;

    virtual Task<void> open_cursor(const std::string& table_name, bool is_dup_sorted) = 0;

    virtual Task<KeyValue> seek(ByteView key) = 0;

    virtual Task<KeyValue> seek_exact(ByteView key) = 0;

    virtual Task<KeyValue> first() = 0;

    virtual Task<KeyValue> last() = 0;

    virtual Task<KeyValue> next() = 0;

    virtual Task<KeyValue> previous() = 0;

    virtual Task<void> close_cursor() = 0;
};

class CursorDupSort : public Cursor {
  public:
    virtual Task<Bytes> seek_both(ByteView key, ByteView value) = 0;

    virtual Task<KeyValue> seek_both_exact(ByteView key, ByteView value) = 0;

    virtual Task<KeyValue> next_dup() = 0;
};

}  // namespace silkworm::db::kv::api
