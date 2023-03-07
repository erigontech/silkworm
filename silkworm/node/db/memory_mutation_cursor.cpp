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
    : memory_mutation_(memory_mutation), config_(config) {
    cursor_ = memory_mutation_.external_txn()->ro_cursor_dup_sort(config);
    memory_cursor_ = std::make_unique<PooledCursor>(memory_mutation_, config);
}

bool MemoryMutationCursor::is_table_cleared() const {
    return memory_mutation_.is_table_cleared(config_.name);
}

bool MemoryMutationCursor::is_entry_deleted(const Bytes& key) const {
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
    return CursorResult{::mdbx::cursor{}, throw_notfound};
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
    return CursorResult{::mdbx::cursor{}, throw_notfound};
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

}  // namespace silkworm::db
