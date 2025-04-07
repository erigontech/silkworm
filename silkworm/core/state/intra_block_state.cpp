// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "intra_block_state.hpp"

#include <bit>

#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/common/util.hpp>

namespace silkworm {

const state::Object* IntraBlockState::get_object(const evmc::address& address) const noexcept {
    auto it{objects_.find(address)};
    if (it != objects_.end()) {
        return &it->second;
    }

    std::optional<Account> account{db_.read_account(address)};
    if (account == std::nullopt) {
        return nullptr;
    }

    auto& obj{objects_[address]};
    obj.initial = *account;
    obj.current = *account;
    return &obj;
}

state::Object* IntraBlockState::get_object(const evmc::address& address) noexcept {
    const auto& self{*this};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
    return const_cast<state::Object*>(self.get_object(address));
}

state::Object& IntraBlockState::get_or_create_object(const evmc::address& address) noexcept {
    auto* obj{get_object(address)};

    if (obj == nullptr) {
        journal_.emplace_back(std::make_unique<state::CreateDelta>(address));
        obj = &objects_[address];
        obj->current = Account{};
    } else if (obj->current == std::nullopt) {
        journal_.emplace_back(std::make_unique<state::UpdateDelta>(address, *obj));
        obj->current = Account{};
    }

    return *obj;
}

bool IntraBlockState::exists(const evmc::address& address) const noexcept {
    auto* obj{get_object(address)};
    return obj != nullptr && obj->current != std::nullopt;
}

bool IntraBlockState::is_dead(const evmc::address& address) const noexcept {
    auto* obj{get_object(address)};
    if (obj == nullptr || obj->current == std::nullopt) {
        return true;
    }
    return obj->current->code_hash == kEmptyHash && obj->current->nonce == 0 && obj->current->balance == 0;
}

void IntraBlockState::create_contract(const evmc::address& address, bool is_code_delegation) noexcept {
    created_.insert(address);
    state::Object created{};
    created.current = Account{};

    std::optional<uint64_t> prev_incarnation{};
    const state::Object* prev{get_object(address)};
    if (prev) {
        created.initial = prev->initial;
        if (prev->current) {
            created.current->balance = prev->current->balance;
            if (prev->initial) {
                prev_incarnation = std::max(prev->current->incarnation, prev->initial->incarnation);
            } else {
                prev_incarnation = prev->current->incarnation;
            }
        } else if (prev->initial) {
            prev_incarnation = prev->initial->incarnation;
        }
        journal_.emplace_back(std::make_unique<state::UpdateDelta>(address, *prev));
    } else {
        journal_.emplace_back(std::make_unique<state::CreateDelta>(address));
    }

    if (!prev_incarnation || prev_incarnation == 0) {
        prev_incarnation = db_.previous_incarnation(address);
    }
    if (prev && prev_incarnation < prev->current->previous_incarnation) {
        prev_incarnation = prev->current->previous_incarnation;
    }

    // EIP-7702 Reincarnation works for accounts which are not delegated designations
    if (!is_code_delegation && !delegated_designations_.contains(address)) {
        created.current->incarnation = *prev_incarnation + 1;
        created.current->previous_incarnation = *prev_incarnation;
    }

    objects_[address] = created;

    auto it{storage_.find(address)};
    if (it == storage_.end()) {
        journal_.emplace_back(std::make_unique<state::StorageCreateDelta>(address));
    } else {
        journal_.emplace_back(std::make_unique<state::StorageWipeDelta>(address, it->second));
        // EIP-7702 Storage cannot be cleared for delegated designations
        if (!is_code_delegation && !delegated_designations_.contains(address)) {
            storage_.erase(address);
        }
    }
}

void IntraBlockState::touch(const evmc::address& address) noexcept {
    const bool inserted{touched_.insert(address).second};

    // See Yellow Paper, Appendix K "Anomalies on the Main Network"
    // and https://github.com/ethereum/EIPs/issues/716
    static constexpr evmc::address kRipemdAddress{0x0000000000000000000000000000000000000003_address};
    if (inserted && address != kRipemdAddress) {
        journal_.emplace_back(std::make_unique<state::TouchDelta>(address));
    }
}

bool IntraBlockState::record_suicide(const evmc::address& address) noexcept {
    const bool inserted{self_destructs_.insert(address).second};
    if (inserted) {
        journal_.emplace_back(std::make_unique<state::SuicideDelta>(address));
    }
    return inserted;
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

bool IntraBlockState::is_self_destructed(const evmc::address& address) const noexcept {
    return self_destructs_.contains(address);
}

// Doesn't create a delta since it's called at the end of a transaction,
// when we don't need snapshots anymore.
void IntraBlockState::destruct(const evmc::address& address) {
    // EIP-7702 Storage cannot be cleared for delegated designations
    if (!delegated_designations_.contains(address)) {
        storage_.erase(address);
    }
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
    journal_.emplace_back(std::make_unique<state::UpdateBalanceDelta>(address, obj.current->balance));
    obj.current->balance = value;
    touch(address);
}

void IntraBlockState::add_to_balance(const evmc::address& address, const intx::uint256& addend) noexcept {
    auto& obj{get_or_create_object(address)};
    journal_.emplace_back(std::make_unique<state::UpdateBalanceDelta>(address, obj.current->balance));
    obj.current->balance += addend;
    touch(address);
}

void IntraBlockState::subtract_from_balance(const evmc::address& address, const intx::uint256& subtrahend) noexcept {
    auto& obj{get_or_create_object(address)};
    journal_.emplace_back(std::make_unique<state::UpdateBalanceDelta>(address, obj.current->balance));
    obj.current->balance -= subtrahend;
    touch(address);
}

uint64_t IntraBlockState::get_nonce(const evmc::address& address) const noexcept {
    auto* obj{get_object(address)};
    return obj && obj->current ? obj->current->nonce : 0;
}

void IntraBlockState::set_nonce(const evmc::address& address, uint64_t nonce) noexcept {
    auto& obj{get_or_create_object(address)};
    journal_.emplace_back(std::make_unique<state::UpdateDelta>(address, obj));
    obj.current->nonce = nonce;
    touch(address);
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

    if (auto it{new_code_.find(code_hash)}; it != new_code_.end()) {
        return {it->second.data(), it->second.size()};
    }

    if (auto it{existing_code_.find(code_hash)}; it != existing_code_.end()) {
        return it->second;
    }

    ByteView code{db_.read_code(address, code_hash)};
    existing_code_[code_hash] = code;
    return code;
}

evmc::bytes32 IntraBlockState::get_code_hash(const evmc::address& address) const noexcept {
    auto* obj{get_object(address)};
    return obj && obj->current ? obj->current->code_hash : kEmptyHash;
}

void IntraBlockState::set_code(const evmc::address& address, ByteView code) noexcept {
    auto& obj{get_or_create_object(address)};
    journal_.emplace_back(std::make_unique<state::UpdateDelta>(address, obj));
    obj.current->code_hash = std::bit_cast<evmc_bytes32>(keccak256(code));

    if (eip7702::is_code_delegated(code)) {
        delegated_designations_.insert(address);
    }
    // Don't overwrite already existing code so that views of it
    // that were previously returned by get_code() are still valid.
    new_code_.try_emplace(obj.current->code_hash, code.begin(), code.end());
    touch(address);
}

evmc_access_status IntraBlockState::access_account(const evmc::address& address) noexcept {
    const bool cold_read{accessed_addresses_.insert(address).second};
    if (cold_read) {
        journal_.emplace_back(std::make_unique<state::AccountAccessDelta>(address));
    }
    return cold_read ? EVMC_ACCESS_COLD : EVMC_ACCESS_WARM;
}

evmc_access_status IntraBlockState::access_storage(const evmc::address& address, const evmc::bytes32& key) noexcept {
    const bool cold_read{accessed_storage_keys_[address].insert(key).second};
    if (cold_read) {
        journal_.emplace_back(std::make_unique<state::StorageAccessDelta>(address, key));
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
    journal_.emplace_back(std::make_unique<state::StorageChangeDelta>(address, key, prev));
}

evmc::bytes32 IntraBlockState::get_transient_storage(const evmc::address& addr, const evmc::bytes32& key) {
    return transient_storage_[addr][key];
}

void IntraBlockState::set_transient_storage(const evmc::address& addr, const evmc::bytes32& key, const evmc::bytes32& value) {
    auto& v = transient_storage_[addr][key];
    const auto prev = v;
    v = value;
    journal_.emplace_back(std::make_unique<state::TransientStorageChangeDelta>(addr, key, prev));
}

void IntraBlockState::write_to_db(uint64_t block_num) {
    db_.begin_block(block_num, objects_.size());

    for (const auto& [address, storage] : storage_) {
        // std::cerr << "Writing do db storage: " << hex(address) << std::endl;
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
        if (!obj.current) {
            continue;
        }
        const auto& code_hash{obj.current->code_hash};

        ByteView code_view;
        if (auto it{new_code_.find(code_hash)}; it != new_code_.end()) {
            code_view = {it->second.data(), it->second.size()};
        }

        const auto is_code_delegated = eip7702::is_code_delegated(code_view);

        if (code_hash != kEmptyHash &&
            (!obj.initial || obj.initial->incarnation != obj.current->incarnation || is_code_delegated)) {
            if (auto it{new_code_.find(code_hash)}; it != new_code_.end()) {
                db_.update_account_code(address, obj.current->incarnation, code_hash, code_view);
            }
        }
    }
}

IntraBlockState::Snapshot IntraBlockState::take_snapshot() const noexcept {
    IntraBlockState::Snapshot snapshot;
    snapshot.journal_size_ = journal_.size();
    snapshot.log_size_ = logs_.size();
    return snapshot;
}

void IntraBlockState::revert_to_snapshot(const IntraBlockState::Snapshot& snapshot) noexcept {
    for (size_t i = journal_.size(); i > snapshot.journal_size_; --i) {
        journal_[i - 1]->revert(*this);
    }
    journal_.resize(snapshot.journal_size_);
    logs_.resize(snapshot.log_size_);
}

void IntraBlockState::finalize_transaction(evmc_revision rev) {
    destruct_suicides();
    if (rev >= EVMC_SPURIOUS_DRAGON) {
        destruct_touched_dead();
    }
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
    created_.clear();
    // EIP-2929
    accessed_addresses_.clear();
    accessed_storage_keys_.clear();

    transient_storage_.clear();
}

void IntraBlockState::add_log(const Log& log) noexcept { logs_.push_back(log); }

}  // namespace silkworm
