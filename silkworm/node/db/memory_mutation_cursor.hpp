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

#include <silkworm/node/db/mdbx.hpp>

#include "memory_mutation.hpp"

namespace silkworm::db {

using Pair = ::mdbx::pair;

class MemoryMutationCursor : public RWCursorDupSort {
  public:
    MemoryMutationCursor(MemoryMutation& memory_mutation, const MapConfig& config);
    ~MemoryMutationCursor() override = default;

    [[nodiscard]] bool is_table_cleared() const;
    [[nodiscard]] bool is_entry_deleted(const Slice& key) const;

    void bind(ROTxn& txn, const MapConfig& config) override;

    [[nodiscard]] ::mdbx::map_handle map() const override;

    [[nodiscard]] bool is_multi_value() const override;

    [[nodiscard]] bool is_dangling() const override;

    CursorResult to_first() override;
    CursorResult to_first(bool throw_notfound) override;
    CursorResult to_previous() override;
    CursorResult to_previous(bool throw_notfound) override;
    [[nodiscard]] CursorResult current() const override;
    [[nodiscard]] CursorResult current(bool throw_notfound) const override;
    CursorResult to_next() override;
    CursorResult to_next(bool throw_notfound) override;
    CursorResult to_last() override;
    CursorResult to_last(bool throw_notfound) override;
    CursorResult find(const Slice& key) override;
    CursorResult find(const Slice& key, bool throw_notfound) override;
    CursorResult lower_bound(const Slice& key) override;
    CursorResult lower_bound(const Slice& key, bool throw_notfound) override;
    CursorResult move(MoveOperation operation, bool throw_notfound) override;
    CursorResult move(MoveOperation operation, const Slice& key, bool throw_notfound) override;
    bool seek(const Slice& key) override;
    [[nodiscard]] bool eof() const override;
    [[nodiscard]] bool on_first() const override;
    [[nodiscard]] bool on_last() const override;
    CursorResult to_previous_last_multi() override;
    CursorResult to_previous_last_multi(bool throw_notfound) override;
    CursorResult to_current_first_multi() override;
    CursorResult to_current_first_multi(bool throw_notfound) override;
    CursorResult to_current_prev_multi() override;
    CursorResult to_current_prev_multi(bool throw_notfound) override;
    CursorResult to_current_next_multi() override;
    CursorResult to_current_next_multi(bool throw_notfound) override;
    CursorResult to_current_last_multi() override;
    CursorResult to_current_last_multi(bool throw_notfound) override;
    CursorResult to_next_first_multi() override;
    CursorResult to_next_first_multi(bool throw_notfound) override;
    CursorResult find_multivalue(const Slice& key, const Slice& value) override;
    CursorResult find_multivalue(const Slice& key, const Slice& value, bool throw_notfound) override;
    CursorResult lower_bound_multivalue(const Slice& key, const Slice& value) override;
    CursorResult lower_bound_multivalue(const Slice& key, const Slice& value, bool throw_notfound) override;
    CursorResult move(MoveOperation operation, const Slice& key, const Slice& value, bool throw_notfound) override;
    [[nodiscard]] std::size_t count_multivalue() const override;
    MDBX_error_t put(const Slice& key, Slice* value, MDBX_put_flags_t flags) noexcept override;
    void insert(const Slice& key, Slice value) override;
    void upsert(const Slice& key, const Slice& value) override;
    void update(const Slice& key, const Slice& value) override;
    bool erase() override;
    bool erase(bool whole_multivalue) override;
    bool erase(const Slice& key) override;
    bool erase(const Slice& key, bool whole_multivalue) override;
    bool erase(const Slice& key, const Slice& value) override;

  private:
    enum class NextType {
        kNormal,
        kDup,
        kNoDup
    };

    CursorResult resolve_priority(CursorResult memory_result, CursorResult db_result, NextType type);
    CursorResult skip_intersection(CursorResult memory_result, CursorResult db_result, NextType type);
    CursorResult next_on_db(NextType type, bool throw_notfound);
    CursorResult next_by_type(NextType type, bool throw_notfound);

    MemoryMutation& memory_mutation_;
    const MapConfig& config_;
    std::unique_ptr<ROCursorDupSort> cursor_;
    std::unique_ptr<RWCursorDupSort> memory_cursor_;
    Pair current_db_entry_;
    Pair current_memory_entry_;
    Pair current_pair_;
    bool is_previous_from_db_{false};
};

}  // namespace silkworm::db
