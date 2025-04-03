// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "delta.hpp"

#include <utility>

#include <silkworm/core/state/intra_block_state.hpp>

namespace silkworm::state {

CreateDelta::CreateDelta(const evmc::address& address) noexcept : address_{address} {}

void CreateDelta::revert(IntraBlockState& state) noexcept { state.objects_.erase(address_); }

UpdateDelta::UpdateDelta(const evmc::address& address, const Object& previous) noexcept
    : address_{address}, previous_{previous} {}

void UpdateDelta::revert(IntraBlockState& state) noexcept { state.objects_[address_] = previous_; }

UpdateBalanceDelta::UpdateBalanceDelta(const evmc::address& address, const intx::uint256& previous) noexcept
    : address_{address}, previous_{previous} {}

void UpdateBalanceDelta::revert(IntraBlockState& state) noexcept {
    state.objects_[address_].current->balance = previous_;
}

SuicideDelta::SuicideDelta(const evmc::address& address) noexcept : address_{address} {}

void SuicideDelta::revert(IntraBlockState& state) noexcept { state.self_destructs_.erase(address_); }

TouchDelta::TouchDelta(const evmc::address& address) noexcept : address_{address} {}

void TouchDelta::revert(IntraBlockState& state) noexcept { state.touched_.erase(address_); }

StorageChangeDelta::StorageChangeDelta(const evmc::address& address, const evmc::bytes32& key,
                                       const evmc::bytes32& previous) noexcept
    : address_{address}, key_{key}, previous_{previous} {}

void StorageChangeDelta::revert(IntraBlockState& state) noexcept { state.storage_[address_].current[key_] = previous_; }

StorageWipeDelta::StorageWipeDelta(const evmc::address& address, Storage storage) noexcept
    : address_{address}, storage_{std::move(storage)} {}

void StorageWipeDelta::revert(IntraBlockState& state) noexcept { state.storage_[address_] = storage_; }

StorageCreateDelta::StorageCreateDelta(const evmc::address& address) noexcept : address_{address} {}

void StorageCreateDelta::revert(IntraBlockState& state) noexcept { state.storage_.erase(address_); }

StorageAccessDelta::StorageAccessDelta(const evmc::address& address, const evmc::bytes32& key) noexcept
    : address_{address}, key_{key} {}

void StorageAccessDelta::revert(IntraBlockState& state) noexcept { state.accessed_storage_keys_[address_].erase(key_); }

AccountAccessDelta::AccountAccessDelta(const evmc::address& address) noexcept : address_{address} {}

void AccountAccessDelta::revert(IntraBlockState& state) noexcept { state.accessed_addresses_.erase(address_); }

TransientStorageChangeDelta::TransientStorageChangeDelta(const evmc::address& address, const evmc::bytes32& key,
                                                         const evmc::bytes32& previous) noexcept
    : address_{address}, key_{key}, previous_{previous} {}

void TransientStorageChangeDelta::revert(IntraBlockState& state) noexcept {
    state.transient_storage_[address_][key_] = previous_;
}

}  // namespace silkworm::state
