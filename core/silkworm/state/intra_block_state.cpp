/*
   Copyright 2020-2021 The Silkworm Authors

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

#include <silkworm/common/cast.hpp>
#include <silkworm/common/util.hpp>

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
        journal_.emplace_back(new state::CreateDelta{address});
        obj = &objects_[address];
        obj->current = Account{};
    } else if (!obj->current) {
        journal_.emplace_back(new state::UpdateDelta{address, *obj});
        obj->current = Account{};
    }

    return *obj;
}

bool IntraBlockState::exists(const evmc::address& address) const noexcept {
    auto* obj{get_object(address)};
    return obj && obj->current;
}

bool IntraBlockState::is_dead(const evmc::address& address) const noexcept {
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
        journal_.emplace_back(new state::UpdateDelta{address, *prev});
    } else {
        journal_.emplace_back(new state::CreateDelta{address});
    }

    if (!prev_incarnation || prev_incarnation == 0) {
        prev_incarnation = db_.previous_incarnation(address);
    }

    created.current->incarnation = *prev_incarnation + 1;

    objects_[address] = created;

    auto it{storage_.find(address)};
    if (it == storage_.end()) {
        journal_.emplace_back(new state::StorageCreateDelta{address});
    } else {
        journal_.emplace_back(new state::StorageWipeDelta{address, it->second});
        storage_.erase(address);
    }
}

void IntraBlockState::touch(const evmc::address& address) noexcept {
    bool inserted{touched_.insert(address).second};

    // See Yellow Paper, Appendix K "Anomalies on the Main Network"
    static constexpr evmc::address kRipemdAddress{0x0000000000000000000000000000000000000003_address};
    if (inserted && address != kRipemdAddress) {
        journal_.emplace_back(new state::TouchDelta{address});
    }
}

void IntraBlockState::record_suicide(const evmc::address& address) noexcept {
    bool inserted{self_destructs_.insert(address).second};
    if (inserted) {
        journal_.emplace_back(new state::SuicideDelta{address});
    }
}

void IntraBlockState::destruct_suicides() {
    for (const auto& address : self_destructs_) {
        destruct(address);
    }
}

void IntraBlockState::destruct_touched_dead() {
    for (const auto& address : touched_) {
        if (is_dead(address)) {
            destruct(address);
        }
    }
}

// Doesn't create a delta since it's called at the end of a transcation,
// when we don't need snapshots anymore.
void IntraBlockState::destruct(const evmc::address& address) {
    storage_.erase(address);
    auto* obj{get_object(address)};
    if (obj) {
        obj->current.reset();
    }
}

intx::uint256 IntraBlockState::get_balance(const evmc::address& address) const noexcept {
    auto* obj{get_object(address)};
    return obj && obj->current ? obj->current->balance : 0;
}

void IntraBlockState::set_balance(const evmc::address& address, const intx::uint256& value) noexcept {
    auto& obj{get_or_create_object(address)};
    journal_.emplace_back(new state::UpdateDelta{address, obj});
    obj.current->balance = value;
    touch(address);
}

void IntraBlockState::add_to_balance(const evmc::address& address, const intx::uint256& addend) noexcept {
    auto& obj{get_or_create_object(address)};
    journal_.emplace_back(new state::UpdateDelta{address, obj});
    obj.current->balance += addend;
    touch(address);
}

void IntraBlockState::subtract_from_balance(const evmc::address& address, const intx::uint256& subtrahend) noexcept {
    auto& obj{get_or_create_object(address)};
    journal_.emplace_back(new state::UpdateDelta{address, obj});
    obj.current->balance -= subtrahend;
    touch(address);
}

uint64_t IntraBlockState::get_nonce(const evmc::address& address) const noexcept {
    auto* obj{get_object(address)};
    return obj && obj->current ? obj->current->nonce : 0;
}

void IntraBlockState::set_nonce(const evmc::address& address, uint64_t nonce) noexcept {
    auto& obj{get_or_create_object(address)};
    journal_.emplace_back(new state::UpdateDelta{address, obj});
    obj.current->nonce = nonce;
}

ByteView IntraBlockState::get_code(const evmc::address& address) const noexcept {
    auto* obj{get_object(address)};

    if (!obj || !obj->current) {
        return {};
    }

    const auto& code_hash{obj->current->code_hash};
    if (code_hash == kEmptyHash) {
        return {};
    }

    if (auto it{code_.find(code_hash)}; it != code_.end()) {
        return it->second;
    }

    code_[code_hash] = db_.read_code(code_hash);
    return code_[code_hash];
}

evmc::bytes32 IntraBlockState::get_code_hash(const evmc::address& address) const noexcept {
    auto* obj{get_object(address)};
    return obj && obj->current ? obj->current->code_hash : kEmptyHash;
}

void IntraBlockState::set_code(const evmc::address& address, Bytes code) noexcept {
    auto& obj{get_or_create_object(address)};
    journal_.emplace_back(new state::UpdateDelta{address, obj});
    obj.current->code_hash = bit_cast<evmc_bytes32>(keccak256(code));

    // Don't overwrite already existing code so that views of it
    // that were previously returned by get_code() are still valid.
    code_.try_emplace(obj.current->code_hash, std::move(code));
}

evmc_access_status IntraBlockState::access_account(const evmc::address& address) noexcept {
    const bool cold_read{accessed_addresses_.insert(address).second};
    if (cold_read) {
        journal_.emplace_back(new state::AccountAccessDelta{address});
    }
    return cold_read ? EVMC_ACCESS_COLD : EVMC_ACCESS_WARM;
}

evmc_access_status IntraBlockState::access_storage(const evmc::address& address, const evmc::bytes32& key) noexcept {
    const bool cold_read{accessed_storage_keys_[address].insert(key).second};
    if (cold_read) {
        journal_.emplace_back(new state::StorageAccessDelta{address, key});
    }
    return cold_read ? EVMC_ACCESS_COLD : EVMC_ACCESS_WARM;
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
        return {};
    }

    state::Storage& storage{storage_[address]};

    if (!original) {
        auto it{storage.current.find(key)};
        if (it != storage.current.end()) {
            return it->second;
        }
    }

    auto it{storage.committed.find(key)};
    if (it != storage.committed.end()) {
        return it->second.original;
    }

    uint64_t incarnation{obj->current->incarnation};
    if (!obj->initial || obj->initial->incarnation != incarnation) {
        return evmc::bytes32{};
    }

    evmc::bytes32 val{db_.read_storage(address, incarnation, key)};

    state::CommittedValue& entry{storage_[address].committed[key]};
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
    journal_.emplace_back(new state::StorageChangeDelta{address, key, prev});
}

void IntraBlockState::write_to_db(uint64_t block_number) {
    db_.begin_block(block_number);

    for (const auto& [address, storage] : storage_) {
        auto it1{objects_.find(address)};
        if (it1 == objects_.end()) {
            continue;
        }
        const state::Object& obj{it1->second};
        if (!obj.current) {
            continue;
        }

        for (const auto& [key, val] : storage.committed) {
            uint64_t incarnation{obj.current->incarnation};
            db_.update_storage(address, incarnation, key, val.initial, val.original);
        }
    }

    for (const auto& [address, obj] : objects_) {
        db_.update_account(address, obj.initial, obj.current);
        if (obj.current && obj.current->code_hash != kEmptyHash &&
            (!obj.initial || obj.initial->incarnation != obj.current->incarnation)) {
            db_.update_account_code(address, obj.current->incarnation, obj.current->code_hash,
                                    code_[obj.current->code_hash]);
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
        state::Storage& storage{x.second};
        for (const auto& [key, val] : storage.current) {
            storage.committed[key].original = val;
        }
        storage.current.clear();
    }
}

void IntraBlockState::clear_journal_and_substate() {
    journal_.clear();

    // and the substate
    self_destructs_.clear();
    logs_.clear();
    touched_.clear();
    refund_ = 0;
    // EIP-2929
    accessed_addresses_.clear();
    accessed_storage_keys_.clear();
}

void IntraBlockState::add_log(const Log& log) noexcept { logs_.push_back(log); }

void IntraBlockState::add_refund(uint64_t addend) noexcept { refund_ += addend; }

void IntraBlockState::subtract_refund(uint64_t subtrahend) noexcept { refund_ -= subtrahend; }

}  // namespace silkworm
