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

    [[nodiscard]] virtual uint32_t cursor_id() const = 0;

    virtual Task<void> open_cursor(const std::string& table_name, bool is_dup_sorted) = 0;

    virtual Task<KeyValue> seek(ByteView key) = 0;

    virtual Task<KeyValue> seek_exact(ByteView key) = 0;

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
