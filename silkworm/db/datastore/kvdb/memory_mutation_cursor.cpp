// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "memory_mutation_cursor.hpp"

#include <silkworm/infra/common/log.hpp>

namespace silkworm::datastore::kvdb {

MemoryMutationCursor::MemoryMutationCursor(MemoryMutation& memory_mutation, const MapConfig& config)
    : memory_mutation_(memory_mutation),
      config_(config),
      current_db_entry_({}, {}, false),
      current_memory_entry_({}, {}, false),
      current_pair_({}, {}, false) {
    cursor_ = memory_mutation_.external_txn()->ro_cursor_dup_sort(config);
    memory_cursor_ = std::make_unique<PooledCursor>(memory_mutation_, config);
}

bool MemoryMutationCursor::is_table_cleared() const {
    return memory_mutation_.is_table_cleared(config_.name);
}

bool MemoryMutationCursor::is_entry_deleted(const Slice& key, const Slice& value) const {
    if (is_multi_value()) {
        return memory_mutation_.is_dup_deleted(config_.name, key, value);
    }
    return memory_mutation_.is_entry_deleted(config_.name, key);
}

void MemoryMutationCursor::bind(ROTxn& txn, const MapConfig& config) {
    memory_mutation_.update_txn(&txn);
    cursor_->bind(txn, config);
    memory_cursor_->bind(txn, config);
}

std::unique_ptr<ROCursor> MemoryMutationCursor::clone() {
    SILKWORM_ASSERT(false);  // not implemented
    return {};
}

::mdbx::map_handle MemoryMutationCursor::map() const {
    return memory_cursor_->map();
}

size_t MemoryMutationCursor::size() const {
    return cursor_->size();
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
    if (is_table_cleared()) {
        return memory_cursor_->to_first(throw_notfound);
    }

    const auto memory_result = memory_cursor_->to_first(false);
    auto db_result = cursor_->to_first(false);

    // Basic checks
    current_db_entry_ = db_result.done ? db_result : CursorResult{{}, {}, false};
    current_memory_entry_ = memory_result.done ? memory_result : CursorResult{{}, {}, false};

    if (memory_result.done) {
        const auto mem_key = memory_result.key.as_string();
        const auto mem_value = memory_result.value.as_string();
        SILK_TRACE << "to_first: memory_result.key=" << mem_key << " memory_result.value=" << mem_value;
    }
    if (db_result.done) {
        const auto db_key = db_result.key.as_string();
        const auto db_value = db_result.value.as_string();
        SILK_TRACE << "to_first: db_result.key=" << db_key << " db_result.value=" << db_value;
    }

    if (db_result.done && db_result.key && is_entry_deleted(db_result.key, db_result.value)) {
        current_pair_ = current_memory_entry_;
        current_db_entry_ = CursorResult{{}, {}, true};
        is_previous_from_db_ = false;
        if (!memory_result.done && throw_notfound) {
            throw_error_notfound();
        }
        return memory_result;
    }

    if (!db_result.done || (db_result.done && !db_result.value)) {
        current_pair_ = current_memory_entry_;
        is_previous_from_db_ = false;
        if (!memory_result.done && throw_notfound) {
            throw_error_notfound();
        }
        return memory_result;
    }

    if (!memory_result.done || (memory_result.done && !memory_result.value)) {
        current_pair_ = current_db_entry_;
        is_previous_from_db_ = true;
        if (!db_result.done && throw_notfound) {
            throw_error_notfound();
        }
        SILK_TRACE << "to_first: db_key=" << db_result.key.as_string() << " db_value=" << db_result.value.as_string();
        return db_result;
    }

    // Determine which one is first
    const auto key_diff = Slice::compare_fast(memory_result.key, db_result.key);
    if (key_diff == 0) {  // memory_result.key == db_result.key
        if (memory_result.value < db_result.value) {
            current_pair_ = current_memory_entry_;
            is_previous_from_db_ = false;
            return memory_result;
        }
        current_pair_ = current_db_entry_;
        is_previous_from_db_ = true;
        return db_result;
    }
    if (key_diff < 0) {  // memory_result.key < db_result.key
        current_pair_ = current_memory_entry_;
        is_previous_from_db_ = false;
        return memory_result;
    }
    // memory_result.key > db_result.key
    current_pair_ = current_db_entry_;
    is_previous_from_db_ = true;
    return db_result;
}

CursorResult MemoryMutationCursor::to_previous() {
    return to_previous(/*throw_notfound =*/true);
}

CursorResult MemoryMutationCursor::to_previous(bool throw_notfound) {
    if (is_table_cleared()) {
        return memory_cursor_->to_previous(throw_notfound);
    }

    const auto memory_result = memory_cursor_->to_previous(false);
    auto db_result = cursor_->to_previous(false);

    db_result = skip_intersection(memory_result, db_result, MoveType::kPrevious);

    // Basic checks
    current_db_entry_ = db_result.done ? db_result : CursorResult{{}, {}, false};
    current_memory_entry_ = memory_result.done ? memory_result : CursorResult{{}, {}, false};

    if (memory_result.done) {
        const auto mem_key = memory_result.key.as_string();
        const auto mem_value = memory_result.value.as_string();
        SILK_TRACE << "to_previous: memory_result.key=" << mem_key << " memory_result.value=" << mem_value;
    }
    if (db_result.done) {
        const auto db_key = db_result.key.as_string();
        const auto db_value = db_result.value.as_string();
        SILK_TRACE << "to_previous: db_result.key=" << db_key << " db_result.value=" << db_value;
    }

    if (db_result.done && db_result.key && is_entry_deleted(db_result.key, db_result.value)) {
        current_pair_ = current_memory_entry_;
        current_db_entry_ = CursorResult{{}, {}, true};
        is_previous_from_db_ = false;
        if (!memory_result.done && throw_notfound) throw_error_notfound();
        return memory_result;
    }

    if (!db_result.done || (db_result.done && !db_result.value)) {
        current_pair_ = current_memory_entry_;
        is_previous_from_db_ = false;
        if (!memory_result.done && throw_notfound) throw_error_notfound();
        return memory_result;
    }

    if (!memory_result.done || (memory_result.done && !memory_result.value)) {
        current_pair_ = current_db_entry_;
        is_previous_from_db_ = true;
        if (!db_result.done && throw_notfound) throw_error_notfound();
        SILK_TRACE << "to_previous: db_key=" << db_result.key.as_string() << " db_value=" << db_result.value.as_string();
        return db_result;
    }

    // Determine which one is previous
    const auto key_diff = Slice::compare_fast(memory_result.key, db_result.key);
    if (key_diff == 0) {  // memory_result.key == db_result.key
        if (memory_result.value > db_result.value) {
            current_pair_ = current_memory_entry_;
            is_previous_from_db_ = false;
            return memory_result;
        }
        current_pair_ = current_db_entry_;
        is_previous_from_db_ = true;
        return db_result;
    }
    if (key_diff < 0) {  // memory_result.key < db_result.key
        current_pair_ = current_memory_entry_;
        is_previous_from_db_ = false;
        return memory_result;
    }
    // memory_result.key > db_result.key
    current_pair_ = current_db_entry_;
    is_previous_from_db_ = true;
    return db_result;
}

CursorResult MemoryMutationCursor::current() const {
    return current(/*throw_notfound =*/true);
}

CursorResult MemoryMutationCursor::current(bool throw_notfound) const {
    if (is_table_cleared()) {
        return memory_cursor_->current(throw_notfound);
    }

    if (!memory_mutation_.has_map(config_.name)) {
        throw_error_nodata();
    }

    if (!current_pair_.done && throw_notfound) throw_error_notfound();
    return current_pair_;
}

CursorResult MemoryMutationCursor::to_next() {
    return to_next(/*throw_notfound =*/true);
}

CursorResult MemoryMutationCursor::to_next(bool throw_notfound) {
    if (is_table_cleared()) {
        return memory_cursor_->to_next(throw_notfound);
    }

    if (is_previous_from_db_) {
        if (current_memory_entry_ == current_db_entry_) {
            current_memory_entry_ = memory_cursor_->to_next(false);
        }
        const auto db_result = next_on_db(MoveType::kNext, false);

        const auto result = resolve_priority(current_memory_entry_, db_result, MoveType::kNext);
        if (!result.done && throw_notfound) {
            throw_error_notfound();
        }
        return result;
    }

    if (current_db_entry_ == current_memory_entry_) {
        current_db_entry_ = cursor_->to_next(false);
    }
    const auto memory_result = memory_cursor_->to_next(false);

    const auto result = resolve_priority(memory_result, current_db_entry_, MoveType::kNext);
    if (!result.done && throw_notfound) {
        throw_error_notfound();
    }
    return result;
}

CursorResult MemoryMutationCursor::to_last() {
    return to_last(/*.throw_notfound=*/true);
}

CursorResult MemoryMutationCursor::to_last(bool throw_notfound) {
    if (is_table_cleared()) {
        return memory_cursor_->to_last(throw_notfound);
    }

    const auto memory_result = memory_cursor_->to_last(false);
    auto db_result = cursor_->to_last(false);

    // Basic checks
    current_db_entry_ = db_result.done ? db_result : CursorResult{{}, {}, false};
    current_memory_entry_ = memory_result.done ? memory_result : CursorResult{{}, {}, false};

    if (memory_result.done) {
        const auto mem_key = memory_result.key.as_string();
        const auto mem_value = memory_result.value.as_string();
        SILK_TRACE << "to_last: memory_result.key=" << mem_key << " memory_result.value=" << mem_value;
    }
    if (db_result.done) {
        const auto db_key = db_result.key.as_string();
        const auto db_value = db_result.value.as_string();
        SILK_TRACE << "to_last: db_result.key=" << db_key << " db_result.value=" << db_value;
    }

    if (db_result.done && db_result.key && is_entry_deleted(db_result.key, db_result.value)) {
        current_pair_ = current_memory_entry_;
        current_db_entry_ = CursorResult{{}, {}, true};
        is_previous_from_db_ = false;
        if (!memory_result.done && throw_notfound) throw_error_notfound();
        return memory_result;
    }

    if (!db_result.done || (db_result.done && !db_result.value)) {
        current_pair_ = current_memory_entry_;
        is_previous_from_db_ = false;
        if (!memory_result.done && throw_notfound) throw_error_notfound();
        return memory_result;
    }

    if (!memory_result.done || (memory_result.done && !memory_result.value)) {
        current_pair_ = current_db_entry_;
        is_previous_from_db_ = true;
        if (!db_result.done && throw_notfound) throw_error_notfound();
        SILK_TRACE << "to_last: db_key=" << db_result.key.as_string() << " db_value=" << db_result.value.as_string();
        return db_result;
    }

    // Determine which one is last
    const auto key_diff = Slice::compare_fast(memory_result.key, db_result.key);
    if (key_diff == 0) {  // memory_result.key == db_result.key
        if (memory_result.value > db_result.value) {
            current_pair_ = current_memory_entry_;
            is_previous_from_db_ = false;
            return memory_result;
        }
        current_pair_ = current_db_entry_;
        is_previous_from_db_ = true;
        return db_result;
    }
    if (key_diff > 0) {  // memory_result.key > db_result.key
        current_pair_ = current_memory_entry_;
        is_previous_from_db_ = false;
        return memory_result;
    }
    // memory_result.key < db_result.key
    current_pair_ = current_db_entry_;
    is_previous_from_db_ = true;
    return db_result;
}

CursorResult MemoryMutationCursor::find(const Slice& key) {
    return find(key, /*.throw_notfound=*/true);
}

//! \details mdbx::cursor::find in mdbx C++ bindings has "key_exact" semantics, that is "Position at specified key".
//! On the other hand, we need mdbx::cursor::lower_bound semantics i.e. "Position at first key greater than or equal
//! to specified key" when comparing and caching memory and database results as required by database overlay.
CursorResult MemoryMutationCursor::find(const Slice& key, bool throw_notfound) {
    if (is_table_cleared()) {
        // We simply delegate to memory cursor, so we need "key_exact" semantics here
        return memory_cursor_->find(key, throw_notfound);
    }

    // We need to compare and cache memory and db results, so we need "key_lowerbound" semantics hereafter
    const auto memory_result = memory_cursor_->lower_bound(key, false);
    SILK_TRACE << "find: memory_result=" << memory_result;

    auto db_result = cursor_->lower_bound(key, false);
    if (db_result.key && is_entry_deleted(db_result.key, db_result.value)) {
        db_result = next_on_db(MoveType::kNext, throw_notfound);
    }
    SILK_TRACE << "find: db_result=" << db_result;

    const auto result = resolve_priority(memory_result, db_result, MoveType::kNone);
    if (!result.done && throw_notfound) throw_error_notfound();

    // In the end, we need to enforce "key_exact" semantics before returning
    if (result.done && result.key != key) {
        return CursorResult{{}, {}, false};
    }
    if (!cursor_->is_multi_value() && current_memory_entry_.key == key && current_db_entry_.key == key) {
        // Choose memory value if both memory and db entries match the specified key
        return current_memory_entry_;
    }
    return result;
}

CursorResult MemoryMutationCursor::lower_bound(const Slice& key) {
    return lower_bound(key, /*.throw_notfound=*/true);
}

CursorResult MemoryMutationCursor::lower_bound(const Slice& key, bool throw_notfound) {
    if (is_table_cleared()) {
        return memory_cursor_->lower_bound(key, throw_notfound);
    }

    const auto memory_result = memory_cursor_->lower_bound(key, false);

    auto db_result = cursor_->lower_bound(key, false);
    if (db_result.key && is_entry_deleted(db_result.key, db_result.value)) {
        db_result = next_on_db(MoveType::kNext, throw_notfound);
    }

    const auto result = resolve_priority(memory_result, db_result, MoveType::kNext);
    if (!result.done && throw_notfound) throw_error_notfound();
    return result;
}

MoveResult MemoryMutationCursor::move(MoveOperation operation, bool throw_notfound) {
    if (operation != MoveOperation::next && operation != MoveOperation::previous) {
        throw std::runtime_error{"MemoryMutationCursor::move not implemented for operation=" + std::to_string(operation)};
    }

    if (is_table_cleared()) {
        return memory_cursor_->move(operation, throw_notfound);
    }

    const auto memory_result = memory_cursor_->move(operation, false);

    auto db_result = cursor_->move(operation, false);
    if (db_result.key && is_entry_deleted(db_result.key, db_result.value)) {
        auto result = operation == MoveOperation::next ? next_on_db(MoveType::kNext, throw_notfound) : previous_on_db(MoveType::kPrevious, throw_notfound);
        std::tie(db_result.done, db_result.key, db_result.value) = std::tuple{result.done, result.key, result.value};
    }

    const auto result = resolve_priority(memory_result, db_result, MoveType::kNext);
    if (!result.done && throw_notfound) throw_error_notfound();

    MoveResult move_result = db_result;
    move_result.done = result.done;
    move_result.key = result.key;
    move_result.value = result.value;
    return move_result;
}

MoveResult MemoryMutationCursor::move(MoveOperation /*operation*/, const Slice& /*key*/, bool /*throw_notfound*/) {
    throw std::runtime_error{"MemoryMutationCursor::move(MoveOperation,const Slice&,bool) not implemented"};
}

bool MemoryMutationCursor::seek(const Slice& key) {
    if (is_table_cleared()) {
        return memory_cursor_->seek(key);
    }

    const auto found_in_memory = memory_cursor_->seek(key);
    CursorResult memory_result{key, found_in_memory ? memory_cursor_->current().value : mdbx::slice{}, found_in_memory};

    bool found_in_db = cursor_->seek(key);
    if (is_entry_deleted(key, memory_result.value)) {
        found_in_db = next_on_db(MoveType::kNext, /*throw_notfound=*/false);
    }
    CursorResult db_result{key, found_in_db ? cursor_->current().value : mdbx::slice{}, found_in_db};

    const auto result = resolve_priority(memory_result, db_result, MoveType::kNext);
    return result.done;
}

bool MemoryMutationCursor::eof() const {
    const auto result = current(/*throw_notfound=*/false);
    if (result.done) return false;
    return memory_cursor_->eof() && cursor_->eof();
}

bool MemoryMutationCursor::on_first() const {
    const auto result = current(/*throw_notfound=*/false);
    if (!result.done) return false;
    return memory_cursor_->on_first() || cursor_->on_first();
}

bool MemoryMutationCursor::on_last() const {
    const auto result = current(/*throw_notfound=*/false);
    if (!result.done) return false;
    return false;
}

CursorResult MemoryMutationCursor::to_previous_last_multi() {
    return to_previous_last_multi(/*.throw_notfound=*/true);
}

CursorResult MemoryMutationCursor::to_previous_last_multi(bool throw_notfound) {
    if (is_table_cleared()) {
        return memory_cursor_->to_previous_last_multi(throw_notfound);
    }

    if (is_previous_from_db_) {
        const auto db_result = previous_on_db(MoveType::kPreviousNoDup, false);
        const auto result = resolve_priority(current_memory_entry_, db_result, MoveType::kPreviousNoDup);
        if (!result.done && throw_notfound) {
            throw_error_notfound();
        }
        return result;
    }

    const auto memory_result = memory_cursor_->to_previous_last_multi(false);
    const auto result = resolve_priority(memory_result, current_db_entry_, MoveType::kPreviousNoDup);
    if (!result.done && throw_notfound) {
        throw_error_notfound();
    }
    return result;
}

CursorResult MemoryMutationCursor::to_current_first_multi() {
    return to_current_first_multi(/*.throw_notfound=*/true);
}

CursorResult MemoryMutationCursor::to_current_first_multi(bool throw_notfound) {
    return CursorResult{{}, {}, throw_notfound};
}

CursorResult MemoryMutationCursor::to_current_prev_multi() {
    return to_current_prev_multi(/*.throw_notfound=*/true);
}

CursorResult MemoryMutationCursor::to_current_prev_multi(bool throw_notfound) {
    if (is_table_cleared()) {
        return memory_cursor_->to_current_prev_multi(throw_notfound);
    }

    if (is_previous_from_db_) {
        const auto db_result = previous_on_db(MoveType::kPreviousDup, false);
        const auto result = resolve_priority(current_memory_entry_, db_result, MoveType::kPreviousDup);
        if (!result.done && throw_notfound) {
            throw_error_notfound();
        }
        return result;
    }

    const auto memory_result = memory_cursor_->to_current_prev_multi(false);
    const auto result = resolve_priority(memory_result, current_db_entry_, MoveType::kPreviousDup);
    if (!result.done && throw_notfound) {
        throw_error_notfound();
    }
    return result;
}

CursorResult MemoryMutationCursor::to_current_next_multi() {
    return to_current_next_multi(/*.throw_notfound=*/true);
}

CursorResult MemoryMutationCursor::to_current_next_multi(bool throw_notfound) {
    if (is_table_cleared()) {
        return memory_cursor_->to_current_next_multi(throw_notfound);
    }

    if (is_previous_from_db_) {
        if (current_memory_entry_ == current_db_entry_) {
            current_memory_entry_ = memory_cursor_->to_next(false);
        }
        const auto db_result = next_on_db(MoveType::kNextDup, false);

        const auto result = resolve_priority(current_memory_entry_, db_result, MoveType::kNextDup);
        if (!result.done && throw_notfound) {
            throw_error_notfound();
        }
        return result;
    }

    if (current_db_entry_ == current_memory_entry_) {
        current_db_entry_ = cursor_->to_next(false);
    }
    const auto memory_result = memory_cursor_->to_current_next_multi(false);

    const auto result = resolve_priority(memory_result, current_db_entry_, MoveType::kNextDup);
    if (!result.done && throw_notfound) {
        throw_error_notfound();
    }
    return result;
}

CursorResult MemoryMutationCursor::to_current_last_multi() {
    return to_current_last_multi(/*.throw_notfound=*/true);
}

CursorResult MemoryMutationCursor::to_current_last_multi(bool throw_notfound) {
    return CursorResult{{}, {}, throw_notfound};
}

CursorResult MemoryMutationCursor::to_next_first_multi() {
    return to_next_first_multi(/*.throw_notfound=*/true);
}

CursorResult MemoryMutationCursor::to_next_first_multi(bool throw_notfound) {
    if (is_table_cleared()) {
        return memory_cursor_->to_next_first_multi(throw_notfound);
    }

    if (is_previous_from_db_) {
        const auto db_result = next_on_db(MoveType::kNextNoDup, false);
        const auto result = resolve_priority(current_memory_entry_, db_result, MoveType::kNextNoDup);
        if (!result.done && throw_notfound) {
            throw_error_notfound();
        }
        return result;
    }

    const auto memory_result = memory_cursor_->to_next_first_multi(false);
    const auto result = resolve_priority(memory_result, current_db_entry_, MoveType::kNextNoDup);
    if (!result.done && throw_notfound) {
        throw_error_notfound();
    }
    return result;
}

CursorResult MemoryMutationCursor::find_multivalue(const Slice& key, const Slice& value) {
    return find_multivalue(key, value, /*.throw_notfound=*/true);
}

CursorResult MemoryMutationCursor::find_multivalue(const Slice& key, const Slice& value, bool throw_notfound) {
    if (is_table_cleared()) {
        return memory_cursor_->find_multivalue(key, value, throw_notfound);
    }

    const auto memory_result = memory_cursor_->find_multivalue(key, value, false);

    auto db_result = cursor_->find_multivalue(key, value, false);
    if (db_result.key && is_entry_deleted(db_result.key, db_result.value)) {
        db_result = next_on_db(MoveType::kNextDup, throw_notfound);
    }

    const auto result = resolve_priority(memory_result, db_result, MoveType::kNextDup);
    if (!result.done && throw_notfound) throw_error_notfound();
    return result;
}

CursorResult MemoryMutationCursor::lower_bound_multivalue(const Slice& key, const Slice& value) {
    return lower_bound_multivalue(key, value, /*.throw_notfound=*/false);
}

CursorResult MemoryMutationCursor::lower_bound_multivalue(const Slice& key, const Slice& value, bool throw_notfound) {
    if (is_table_cleared()) {
        return memory_cursor_->lower_bound_multivalue(key, value, throw_notfound);
    }

    const auto memory_result = memory_cursor_->lower_bound_multivalue(key, value, false);

    auto db_result = cursor_->lower_bound_multivalue(key, value, false);
    if (db_result.key && is_entry_deleted(db_result.key, db_result.value)) {
        db_result = next_on_db(MoveType::kNextDup, throw_notfound);
    }

    const auto result = resolve_priority(memory_result, db_result, MoveType::kNextDup);
    if (!result.done && throw_notfound) throw_error_notfound();
    return result;
}

MoveResult MemoryMutationCursor::move(MoveOperation /*operation*/, const Slice& /*key*/, const Slice& /*value*/, bool /*throw_notfound*/) {
    throw std::runtime_error{"MemoryMutationCursor::move(MoveOperation,const Slice&,const Slice&,bool) not implemented"};
}

size_t MemoryMutationCursor::count_multivalue() const {
    size_t count{0};
    return count;
}

MDBX_error_t MemoryMutationCursor::put(const Slice& key, Slice* value, MDBX_put_flags_t flags) noexcept {
    return memory_mutation_->put(memory_cursor_->map(), key, value, flags);
}

void MemoryMutationCursor::insert(const Slice& key, Slice value) {
    ::mdbx::error::success_or_throw(put(key, &value, MDBX_put_flags_t(::mdbx::put_mode::insert_unique)));
}

void MemoryMutationCursor::upsert(const Slice& key, const Slice& value) {
    memory_mutation_.upsert(config_, key, value);
}

void MemoryMutationCursor::update(const Slice& key, const Slice& value) {
    // Key *MUST* exist to perform update, so
    const auto result{find(key)};
    if (!result.done) {
        throw_error_notfound();
    }
    // *UPSERT* because we need to insert key in memory if it doesn't exist
    memory_mutation_.upsert(config_, key, value);
}

void MemoryMutationCursor::append(const Slice& key, const Slice& value) {
    Slice value_out = value;
    ::mdbx::error::success_or_throw(put(key, &value_out, MDBX_put_flags_t::MDBX_APPENDDUP));
}

bool MemoryMutationCursor::erase() {
    return erase(/*whole_multivalue=*/false);
}

bool MemoryMutationCursor::erase(bool whole_multivalue) {
    const auto current_result = current(/*throw_notfound=*/false);
    if (!current_result.done) {
        return false;
    }
    if (whole_multivalue) {
        return memory_mutation_.erase(config_, current_result.key);
    }
    return memory_mutation_.erase(config_, current_result.key, current_result.value);
}

bool MemoryMutationCursor::erase(const Slice& key) {
    return erase(key, /*whole_multivalue=*/true);
}

bool MemoryMutationCursor::erase(const Slice& key, bool whole_multivalue) {
    const auto find_result = find(key, /*throw_notfound=*/false);
    if (!find_result.done) {
        return false;
    }
    if (whole_multivalue) {
        return memory_mutation_.erase(config_, find_result.key);
    }
    return memory_mutation_.erase(config_, find_result.key, find_result.value);
}

bool MemoryMutationCursor::erase(const Slice& key, const Slice& value) {
    return memory_mutation_.erase(config_, key, value);
}

CursorResult MemoryMutationCursor::next_on_db(MemoryMutationCursor::MoveType type, bool throw_notfound) {
    CursorResult result = next_by_type(type, throw_notfound);
    if (!result.done) return result;

    while (result.key && result.value && is_entry_deleted(result.key, result.value)) {
        result = next_by_type(type, throw_notfound);
        if (!result.done) return result;
    }

    return result;
}

CursorResult MemoryMutationCursor::next_by_type(MemoryMutationCursor::MoveType type, bool throw_notfound) {
    switch (type) {
        case MoveType::kNext: {
            return cursor_->to_next(throw_notfound);
        }
        case MoveType::kNextDup: {
            return cursor_->to_current_next_multi(throw_notfound);
        }
        case MoveType::kNextNoDup: {
            return cursor_->to_next_first_multi(throw_notfound);
        }
        default: {  // Avoid GCC complaining w/ error: control reaches end of non-void function
            return CursorResult{{}, {}, false};
        }
    }
}

CursorResult MemoryMutationCursor::previous_on_db(MemoryMutationCursor::MoveType type, bool throw_notfound) {
    CursorResult result = previous_by_type(type, throw_notfound);
    if (!result.done) return result;

    while (result.key && result.value && is_entry_deleted(result.key, result.value)) {
        result = previous_by_type(type, throw_notfound);
        if (!result.done) return result;
    }

    return result;
}

CursorResult MemoryMutationCursor::previous_by_type(MemoryMutationCursor::MoveType type, bool throw_notfound) {
    switch (type) {
        case MoveType::kPrevious: {
            return cursor_->to_previous(throw_notfound);
        }
        case MoveType::kPreviousDup: {
            return cursor_->to_current_prev_multi(throw_notfound);
        }
        case MoveType::kPreviousNoDup: {
            return cursor_->to_previous_last_multi(throw_notfound);
        }
        default: {  // Avoid GCC complaining w/ error: control reaches end of non-void function
            return CursorResult{{}, {}, false};
        }
    }
}

CursorResult MemoryMutationCursor::resolve_priority(CursorResult memory_result, CursorResult db_result, MoveType type) {
    SILK_TRACE << "resolve_priority: memory_result.done=" << memory_result.done << " db_result.done=" << db_result.done;

    if (!memory_result.done && !db_result.done) {
        return CursorResult{{}, {}, false};
    }

    db_result = skip_intersection(memory_result, db_result, type);

    current_db_entry_ = db_result.done ? db_result : CursorResult{{}, {}, false};
    current_memory_entry_ = memory_result.done ? memory_result : CursorResult{{}, {}, false};

    SILK_TRACE << "resolve_priority: current_memory_entry_=" << current_memory_entry_ << " current_db_entry_=" << current_db_entry_;

    if (memory_result.done) {
        const auto mem_key = memory_result.key.as_string();
        const auto mem_value = memory_result.value.as_string();
        SILK_TRACE << " memory_result.key=" << mem_key << " memory_result.value=" << mem_value;
    }
    if (db_result.done) {
        const auto db_key = db_result.key.as_string();
        const auto db_value = db_result.value.as_string();
        SILK_TRACE << " db_result.key=" << db_key << " db_result.value=" << db_value;
    }

    if (memory_result.done && db_result.done) {
        if (memory_result.key == db_result.key) {
            is_previous_from_db_ = memory_result.value > db_result.value;
        } else {
            is_previous_from_db_ = memory_result.key > db_result.key;
        }
    } else {
        // At least one result is KO: so get from db if its result is OK, otherwise from memory anyway
        is_previous_from_db_ = db_result.done;
    }

    if (is_previous_from_db_) {
        current_pair_ = current_db_entry_;
    } else {
        current_pair_ = current_memory_entry_;
    }

    return current_pair_;
}

CursorResult MemoryMutationCursor::skip_intersection(CursorResult memory_result, CursorResult db_result, MoveType type) {
    CursorResult new_db_result = db_result;

    // Check for duplicates
    if (memory_result.done && db_result.done && memory_result.key == db_result.key) {
        bool skip{false};
        if (type == MoveType::kNext || type == MoveType::kPrevious) {
            skip = !cursor_->is_multi_value() || memory_result.value == db_result.value;
        } else {
            skip = memory_result.value == db_result.value;
        }
        if (skip) {
            if (type == MoveType::kNext || type == MoveType::kNextDup || type == MoveType::kNextNoDup) {
                new_db_result = next_on_db(type, /*.throw_notfound=*/false);
            } else if (type == MoveType::kPrevious || type == MoveType::kPreviousDup || type == MoveType::kPreviousNoDup) {
                new_db_result = previous_on_db(type, /*.throw_notfound=*/false);
            }
        }
    }

    return new_db_result;
}

void MemoryMutationCursor::throw_error_nodata() {
    mdbx::error::throw_exception(MDBX_error_t::MDBX_ENODATA);
}

void MemoryMutationCursor::throw_error_notfound() {
    mdbx::error::throw_exception(MDBX_error_t::MDBX_NOTFOUND);
}

}  // namespace silkworm::datastore::kvdb
