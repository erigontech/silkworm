/*
   Copyright 2020 The Silkworm Authors

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

#include "intra_block_state.hpp"

#include <cstring>
#include <ethash/keccak.hpp>
#include <silkworm/common/util.hpp>
#include <silkworm/execution/protocol_param.hpp>

namespace silkworm {

state::Object* IntraBlockState::get_object(const evmc::address& address) const noexcept {
    auto it{objects_.find(address)};
    if (it != objects_.end()) {
        return &it->second;
    }

    std::optional<Account> account{db_.read_account(address)};
    if (!account) {
        return nullptr;
    }

    auto& obj{objects_[address]};
    obj.initial = *account;
    obj.current = *account;
    return &obj;
}

state::Object& IntraBlockState::get_or_create_object(const evmc::address& address) noexcept {
    auto* obj{get_object(address)};

    if (!obj) {
        journal_.push_back(std::make_unique<state::CreateDelta>(address));
        obj = &objects_[address];
        obj->current = Account{};
    } else if (!obj->current) {
        journal_.push_back(std::make_unique<state::UpdateDelta>(address, *obj));
        obj->current = Account{};
    }

    return *obj;
}

bool IntraBlockState::exists(const evmc::address& address) const noexcept {
    auto* obj{get_object(address)};
    return obj && obj->current;
}

bool IntraBlockState::dead(const evmc::address& address) const noexcept {
    auto* obj{get_object(address)};
    if (!obj || !obj->current) {
        return true;
    }
    return obj->current->code_hash == kEmptyHash && obj->current->nonce == 0 && obj->current->balance == 0;
}

void IntraBlockState::create_contract(const evmc::address& address) noexcept {
    state::Object created{};
    created.current = Account{};

    std::optional<uint64_t> prev_incarnation{};
    const state::Object* prev{get_object(address)};
    if (prev) {
        created.initial = prev->initial;
        if (prev->current) {
            created.current->balance = prev->current->balance;
            prev_incarnation = prev->current->incarnation;
        } else if (prev->initial) {
            prev_incarnation = prev->initial->incarnation;
        }
        journal_.push_back(std::make_unique<state::UpdateDelta>(address, *prev));
    } else {
        journal_.push_back(std::make_unique<state::CreateDelta>(address));
    }

    if (!prev_incarnation || prev_incarnation == 0) {
        prev_incarnation = db_.previous_incarnation(address);
    }

    created.current->incarnation = *prev_incarnation + 1;

    objects_[address] = created;

    auto it{storage_.find(address)};
    if (it != storage_.end()) {
        journal_.push_back(std::make_unique<state::StorageWipeDelta>(address, it->second));
        storage_.erase(address);
    }
}

void IntraBlockState::touch(const evmc::address& address) noexcept {
    bool inserted{touched_.insert(address).second};
    if (inserted) {
        journal_.push_back(std::make_unique<state::TouchDelta>(address));
    }
}

void IntraBlockState::record_suicide(const evmc::address& address) noexcept {
    bool inserted{self_destructs_.insert(address).second};
    if (inserted) {
        journal_.push_back(std::make_unique<state::SuicideDelta>(address));
    }
}

void IntraBlockState::destruct_suicides() {
    for (const evmc::address& a : self_destructs_) {
        destruct(a);
    }
}

void IntraBlockState::destruct_touched_dead() {
    for (const evmc::address& a : touched_) {
        if (dead(a)) {
            destruct(a);
        }
    }
}

// Doesn't create a delta since it's called at the end of a transcation,
// when we don't need snapshots anymore.
void IntraBlockState::destruct(const evmc::address& address) {
    storage_.erase(address);
    auto* obj{get_object(address)};
    if (!obj) {
        return;
    }
    obj->current.reset();
    obj->code.reset();
}

intx::uint256 IntraBlockState::get_balance(const evmc::address& address) const noexcept {
    auto* obj{get_object(address)};
    return obj && obj->current ? obj->current->balance : 0;
}

void IntraBlockState::set_balance(const evmc::address& address, const intx::uint256& value) noexcept {
    auto& obj{get_or_create_object(address)};
    journal_.push_back(std::make_unique<state::UpdateDelta>(address, obj));
    obj.current->balance = value;
    touch(address);
}

void IntraBlockState::add_to_balance(const evmc::address& address, const intx::uint256& addend) noexcept {
    auto& obj{get_or_create_object(address)};
    journal_.push_back(std::make_unique<state::UpdateDelta>(address, obj));
    obj.current->balance += addend;
    touch(address);
}

void IntraBlockState::subtract_from_balance(const evmc::address& address, const intx::uint256& subtrahend) noexcept {
    auto& obj{get_or_create_object(address)};
    journal_.push_back(std::make_unique<state::UpdateDelta>(address, obj));
    obj.current->balance -= subtrahend;
    touch(address);
}

uint64_t IntraBlockState::get_nonce(const evmc::address& address) const noexcept {
    auto* obj{get_object(address)};
    return obj && obj->current ? obj->current->nonce : 0;
}

void IntraBlockState::set_nonce(const evmc::address& address, uint64_t nonce) noexcept {
    auto& obj{get_or_create_object(address)};
    journal_.push_back(std::make_unique<state::UpdateDelta>(address, obj));
    obj.current->nonce = nonce;
}

ByteView IntraBlockState::get_code(const evmc::address& address) const noexcept {
    auto* obj{get_object(address)};

    if (!obj || !obj->current || obj->current->code_hash == kEmptyHash) {
        return {};
    }
    if (obj->code) {
        return *obj->code;
    }

    obj->code = db_.read_code(obj->current->code_hash);

    return *obj->code;
}

evmc::bytes32 IntraBlockState::get_code_hash(const evmc::address& address) const noexcept {
    auto* obj{get_object(address)};
    return obj && obj->current ? obj->current->code_hash : kEmptyHash;
}

void IntraBlockState::set_code(const evmc::address& address, ByteView code) noexcept {
    auto& obj{get_or_create_object(address)};
    journal_.push_back(std::make_unique<state::UpdateDelta>(address, obj));
    obj.code = code;
    ethash::hash256 hash{keccak256(code)};
    std::memcpy(obj.current->code_hash.bytes, hash.bytes, kHashLength);
}

evmc::bytes32 IntraBlockState::get_current_storage(const evmc::address& address,
                                                   const evmc::bytes32& key) const noexcept {
    return get_storage(address, key, /*original=*/false);
}

evmc::bytes32 IntraBlockState::get_original_storage(const evmc::address& address,
                                                    const evmc::bytes32& key) const noexcept {
    return get_storage(address, key, /*original=*/true);
}

evmc::bytes32 IntraBlockState::get_storage(const evmc::address& address, const evmc::bytes32& key,
                                           bool original) const noexcept {
    auto* obj{get_object(address)};
    if (!obj || !obj->current) {
        return evmc::bytes32{};
    }

    state::Storage& storage{storage_[address]};

    if (!original) {
        auto it{storage.current.find(key)};
        if (it != storage.current.end()) {
            return it->second;
        }
    }

    auto it{storage.commited.find(key)};
    if (it != storage.commited.end()) {
        return it->second.original;
    }

    uint64_t incarnation{obj->current->incarnation};
    if (!obj->initial || obj->initial->incarnation != incarnation) {
        return evmc::bytes32{};
    }

    evmc::bytes32 val{db_.read_storage(address, incarnation, key)};

    state::CommitedValue& entry{storage_[address].commited[key]};
    entry.initial = val;
    entry.original = val;

    return val;
}

void IntraBlockState::set_storage(const evmc::address& address, const evmc::bytes32& key,
                                  const evmc::bytes32& value) noexcept {
    evmc::bytes32 prev{get_current_storage(address, key)};
    if (prev == value) {
        return;
    }
    storage_[address].current[key] = value;
    journal_.push_back(std::make_unique<state::StorageChangeDelta>(address, key, prev));
}

void IntraBlockState::write_to_db(uint64_t block_number) {
    db_.begin_block(block_number);

    for (const auto& x : storage_) {
        const evmc::address& address{x.first};
        const state::Storage& storage{x.second};

        auto it1{objects_.find(address)};
        if (it1 == objects_.end()) {
            continue;
        }
        const state::Object& obj{it1->second};
        if (!obj.current) {
            continue;
        }

        for (const auto& entry : storage.commited) {
            const evmc::bytes32& key{entry.first};
            const state::CommitedValue& val{entry.second};
            uint64_t incarnation{obj.current->incarnation};
            db_.update_storage(address, incarnation, key, val.initial, val.original);
        }
    }

    for (const auto& entry : objects_) {
        const evmc::address& address{entry.first};
        const state::Object& obj{entry.second};
        db_.update_account(address, obj.initial, obj.current);
        if (obj.current && obj.code && (!obj.initial || obj.initial->incarnation != obj.current->incarnation)) {
            db_.update_account_code(address, obj.current->incarnation, obj.current->code_hash, *obj.code);
        }
    }
}

IntraBlockState::Snapshot IntraBlockState::take_snapshot() const noexcept {
    IntraBlockState::Snapshot snapshot;
    snapshot.journal_size_ = journal_.size();
    snapshot.log_size_ = logs_.size();
    snapshot.refund_ = refund_;
    return snapshot;
}

void IntraBlockState::revert_to_snapshot(const IntraBlockState::Snapshot& snapshot) noexcept {
    for (size_t i = journal_.size(); i > snapshot.journal_size_; --i) {
        journal_[i - 1]->revert(*this);
    }
    journal_.resize(snapshot.journal_size_);
    logs_.resize(snapshot.log_size_);
    refund_ = snapshot.refund_;
}

void IntraBlockState::finalize_transaction() {
    for (auto& x : storage_) {
        state::Storage& s{x.second};
        for (const auto& entry : s.current) {
            s.commited[entry.first].original = entry.second;
        }
        s.current.clear();
    }
}

void IntraBlockState::clear_journal_and_substate() {
    journal_.clear();

    // and the substate
    self_destructs_.clear();
    logs_.clear();
    touched_.clear();
    refund_ = 0;
}

void IntraBlockState::add_log(const Log& log) noexcept { logs_.push_back(log); }

void IntraBlockState::add_refund(uint64_t addend) noexcept { refund_ += addend; }

void IntraBlockState::subtract_refund(uint64_t subtrahend) noexcept { refund_ -= subtrahend; }

uint64_t IntraBlockState::total_refund() const noexcept {
    return refund_ + fee::kRSelfDestruct * self_destructs_.size();
}
}  // namespace silkworm
