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

#include "memory_mutation_cursor.hpp"

namespace silkworm::db {

MemoryMutationCursor::MemoryMutationCursor(MemoryMutation& memory_mutation, const MapConfig& config)
    : memory_mutation_(memory_mutation),
      config_(config),
      current_db_entry_({}, {}),
      current_memory_entry_({}, {}),
      current_pair_({}, {}) {
    cursor_ = memory_mutation_.external_txn()->ro_cursor_dup_sort(config);
    memory_cursor_ = std::make_unique<PooledCursor>(memory_mutation_, config);
}

bool MemoryMutationCursor::is_table_cleared() const {
    return memory_mutation_.is_table_cleared(config_.name);
}

bool MemoryMutationCursor::is_entry_deleted(const Slice& key) const {
    return memory_mutation_.is_entry_deleted(config_.name, key);
}

void MemoryMutationCursor::bind(ROTxn& txn, const MapConfig& config) {
    memory_mutation_.update_txn(&txn);
    cursor_->bind(txn, config);
    memory_cursor_->bind(txn, config);
}

::mdbx::map_handle MemoryMutationCursor::map() const {
    return memory_cursor_->map();
}

bool MemoryMutationCursor::is_multi_value() const {
    return cursor_->is_multi_value();
}

bool MemoryMutationCursor::is_dangling() const {
    return cursor_->is_dangling();
}

CursorResult MemoryMutationCursor::to_first() {
    return to_first(/*throw_notfound =*/true);
}

CursorResult MemoryMutationCursor::to_first(bool throw_notfound) {
    const auto memory_result = memory_cursor_->to_first(false);
    if (is_table_cleared()) {
        return memory_result;
    }

    auto db_result = cursor_->to_first(false);

    if (db_result.key && is_entry_deleted(db_result.key)) {
        db_result = next_on_db(NextType::kNormal, throw_notfound);
    }

    const auto result = resolve_priority(memory_result, db_result, NextType::kNormal);
    if (!result.done && throw_notfound) throw_error_notfound();
    return result;
}

CursorResult MemoryMutationCursor::to_previous() {
    return to_previous(/*throw_notfound =*/true);
}

CursorResult MemoryMutationCursor::to_previous(bool throw_notfound) {
    return CursorResult{::mdbx::cursor{}, throw_notfound};
}

CursorResult MemoryMutationCursor::current() const {
    return current(/*throw_notfound =*/true);
}

CursorResult MemoryMutationCursor::current(bool throw_notfound) const {
    return CursorResult{::mdbx::cursor{}, throw_notfound};
}

CursorResult MemoryMutationCursor::to_next() {
    return to_next(/*throw_notfound =*/true);
}

CursorResult MemoryMutationCursor::to_next(bool throw_notfound) {
    return CursorResult{::mdbx::cursor{}, throw_notfound};
}

CursorResult MemoryMutationCursor::to_last() {
    return to_last(/*throw_notfound =*/true);
}

CursorResult MemoryMutationCursor::to_last(bool throw_notfound) {
    auto memory_result = memory_cursor_->to_last(false);
    if (is_table_cleared()) {
        return memory_result;
    }

    auto db_result = cursor_->to_last(false);

    db_result = skip_intersection(memory_result, db_result, NextType::kNormal);

    // Basic checks
    current_db_entry_ = db_result.done && db_result.value ? db_result : Pair{{}, {}};
    current_memory_entry_ = memory_result.done && memory_result.value ? memory_result : Pair{{}, {}};

    if (db_result.done && db_result.key && is_entry_deleted(db_result.key)) {
        current_db_entry_ = Pair{{}, {}};
        is_previous_from_db_ = true;
        if (!memory_result.done && throw_notfound) throw_error_notfound();
        return memory_result;
    }

    if (db_result.done && !db_result.value) {
        is_previous_from_db_ = false;
        if (!memory_result.done && throw_notfound) throw_error_notfound();
        return memory_result;
    }

    if (!memory_result.done || (memory_result.done && !memory_result.value)) {
        is_previous_from_db_ = true;
        if (!db_result.done && throw_notfound) throw_error_notfound();
        return db_result;
    }

    // Determine which one is last
    const auto key_diff = Slice::compare_fast(memory_result.key, db_result.key);
    if (key_diff == 0) {
        if (memory_result.value > db_result.value) {
            current_db_entry_ = Pair{{}, {}};
            is_previous_from_db_ = false;
            return memory_result;
        } else {
            current_memory_entry_ = Pair{{}, {}};
            is_previous_from_db_ = true;
            return db_result;
        }
    } else if (key_diff > 0) {
        current_db_entry_ = Pair{{}, {}};
        is_previous_from_db_ = false;
        return memory_result;
    } else {  // key_diff < 0
        current_memory_entry_ = Pair{{}, {}};
        is_previous_from_db_ = true;
        return db_result;
    }
}

CursorResult MemoryMutationCursor::find(const Slice& key) {
    return find(key, /*throw_notfound =*/true);
}

CursorResult MemoryMutationCursor::find(const Slice& /*key*/, bool throw_notfound) {
    return CursorResult{::mdbx::cursor{}, throw_notfound};
}

CursorResult MemoryMutationCursor::lower_bound(const Slice& key) {
    return lower_bound(key, /*throw_notfound =*/true);
}

CursorResult MemoryMutationCursor::lower_bound(const Slice& /*key*/, bool throw_notfound) {
    return CursorResult{::mdbx::cursor{}, throw_notfound};
}

CursorResult MemoryMutationCursor::move(MoveOperation /*operation*/, bool throw_notfound) {
    return CursorResult{::mdbx::cursor{}, throw_notfound};
}

CursorResult MemoryMutationCursor::move(MoveOperation /*operation*/, const Slice& /*key*/, bool throw_notfound) {
    return CursorResult{::mdbx::cursor{}, throw_notfound};
}

bool MemoryMutationCursor::seek(const Slice& /*key*/) {
    return false;
}

bool MemoryMutationCursor::eof() const {
    return true;
}

bool MemoryMutationCursor::on_first() const {
    return false;
}

bool MemoryMutationCursor::on_last() const {
    return false;
}

CursorResult MemoryMutationCursor::to_previous_last_multi() {
    return to_previous_last_multi(/*throw_notfound =*/true);
}

CursorResult MemoryMutationCursor::to_previous_last_multi(bool throw_notfound) {
    return CursorResult{::mdbx::cursor{}, throw_notfound};
}

CursorResult MemoryMutationCursor::to_current_first_multi() {
    return to_current_first_multi(/*throw_notfound =*/true);
}

CursorResult MemoryMutationCursor::to_current_first_multi(bool throw_notfound) {
    return CursorResult{::mdbx::cursor{}, throw_notfound};
}

CursorResult MemoryMutationCursor::to_current_prev_multi() {
    return to_current_prev_multi(/*throw_notfound =*/true);
}

CursorResult MemoryMutationCursor::to_current_prev_multi(bool throw_notfound) {
    return CursorResult{::mdbx::cursor{}, throw_notfound};
}

CursorResult MemoryMutationCursor::to_current_next_multi() {
    return to_current_next_multi(/*throw_notfound =*/true);
}

CursorResult MemoryMutationCursor::to_current_next_multi(bool throw_notfound) {
    return CursorResult{::mdbx::cursor{}, throw_notfound};
}

CursorResult MemoryMutationCursor::to_current_last_multi() {
    return to_current_last_multi(/*throw_notfound =*/true);
}

CursorResult MemoryMutationCursor::to_current_last_multi(bool throw_notfound) {
    return CursorResult{::mdbx::cursor{}, throw_notfound};
}

CursorResult MemoryMutationCursor::to_next_first_multi() {
    return to_next_first_multi(/*throw_notfound =*/true);
}

CursorResult MemoryMutationCursor::to_next_first_multi(bool throw_notfound) {
    return CursorResult{::mdbx::cursor{}, throw_notfound};
}

CursorResult MemoryMutationCursor::find_multivalue(const Slice& key, const Slice& value) {
    return find_multivalue(key, value, /*throw_notfound =*/true);
}

CursorResult MemoryMutationCursor::find_multivalue(const Slice& /*key*/, const Slice& /*value*/, bool throw_notfound) {
    return CursorResult{::mdbx::cursor{}, throw_notfound};
}

CursorResult MemoryMutationCursor::lower_bound_multivalue(const Slice& key, const Slice& value) {
    return lower_bound_multivalue(key, value, /*throw_notfound =*/false);
}

CursorResult MemoryMutationCursor::lower_bound_multivalue(const Slice& /*key*/, const Slice& /*value*/, bool throw_notfound) {
    return CursorResult{::mdbx::cursor{}, throw_notfound};
}

CursorResult MemoryMutationCursor::move(MoveOperation /*operation*/, const Slice& /*key*/, const Slice& /*value*/, bool throw_notfound) {
    return CursorResult{::mdbx::cursor{}, throw_notfound};
}

std::size_t MemoryMutationCursor::count_multivalue() const {
    return 0;
}

MDBX_error_t MemoryMutationCursor::put(const Slice& /*key*/, Slice* /*value*/, MDBX_put_flags_t /*flags*/) noexcept {
    return MDBX_SUCCESS;
}

void MemoryMutationCursor::insert(const Slice& /*key*/, Slice /*value*/) {
}

void MemoryMutationCursor::upsert(const Slice& /*key*/, const Slice& /*value*/) {
}

void MemoryMutationCursor::update(const Slice& /*key*/, const Slice& /*value*/) {
}

bool MemoryMutationCursor::erase() {
    return false;
}

bool MemoryMutationCursor::erase(bool /*whole_multivalue*/) {
    return false;
}

bool MemoryMutationCursor::erase(const Slice& /*key*/) {
    return false;
}

bool MemoryMutationCursor::erase(const Slice& /*key*/, bool /*whole_multivalue*/) {
    return false;
}

bool MemoryMutationCursor::erase(const Slice& /*key*/, const Slice& /*value*/) {
    return false;
}

CursorResult MemoryMutationCursor::next_on_db(MemoryMutationCursor::NextType type, bool throw_notfound) {
    CursorResult result = next_by_type(type, throw_notfound);
    if (!result) return result;

    while (result.key && result.value && is_entry_deleted(result.key)) {
        result = next_by_type(type, throw_notfound);
        if (!result) return result;
    }

    return result;
}

CursorResult MemoryMutationCursor::next_by_type(MemoryMutationCursor::NextType type, bool throw_notfound) {
    switch (type) {
        case NextType::kNormal: {
            return cursor_->to_next(throw_notfound);
        }
        case NextType::kDup: {
            return cursor_->to_current_next_multi(throw_notfound);
        }
        case NextType::kNoDup: {
            return cursor_->to_next_first_multi(throw_notfound);
        }
        default: {
            return CursorResult{::mdbx::cursor{}, throw_notfound};
        }
    }
}

CursorResult MemoryMutationCursor::resolve_priority(CursorResult memory_result, CursorResult db_result, NextType type) {
    if (memory_result.done && memory_result.value.empty() && db_result.value.empty()) {
        return memory_result;
    }

    db_result = skip_intersection(memory_result, db_result, type);
    if (!db_result) {
        return db_result;
    }

    current_db_entry_ = db_result.value ? db_result : Pair{{}, {}};
    current_memory_entry_ = memory_result.done && memory_result.value ? memory_result : Pair{{}, {}};

    if (memory_result.done) {
        if (memory_result.key == db_result.key) {
            is_previous_from_db_ = db_result.value && (!memory_result.value || memory_result.value > db_result.value);
        } else {
            is_previous_from_db_ = db_result.value && (!memory_result.key || memory_result.key > db_result.key);
        }
    } else {
        is_previous_from_db_ = db_result.value;
    }

    if (is_previous_from_db_) {
        current_pair_ = current_db_entry_;
    } else {
        current_pair_ = current_memory_entry_;
    }

    // We need to copy result because creating CursorResult requires a mdbx::cursor instance
    auto result = is_previous_from_db_ ? db_result : memory_result;
    result.key = current_pair_.key;
    result.value = current_pair_.value;
    result.done = true;
    return result;
}

CursorResult MemoryMutationCursor::skip_intersection(CursorResult memory_result, CursorResult db_result, NextType type) {
    auto new_db_key = db_result.key;
    auto new_db_value = db_result.value;

    // Check for duplicates
    if (memory_result.done && db_result.done && memory_result.key == db_result.key) {
        bool skip{false};
        if (type == NextType::kNormal) {
            skip = !cursor_->is_multi_value() || memory_result.value == db_result.value;
        } else {
            skip = memory_result.value == db_result.value;
        }
        if (skip) {
            const auto next_result = next_on_db(type, /*.throw_notfound*/ false);
            if (next_result) {
                new_db_key = next_result.key;
                new_db_value = next_result.value;
            }
        }
    }

    // We need to copy result because creating CursorResult requires a mdbx::cursor instance
    auto result = db_result;
    result.key = new_db_key;
    result.value = new_db_value;
    return result;
}

void MemoryMutationCursor::throw_error_notfound() {
    mdbx::error::throw_exception(MDBX_error_t::MDBX_NOTFOUND);
}

}  // namespace silkworm::db
