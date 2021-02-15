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

#include "delta.hpp"

#include <utility>

#include "intra_block_state.hpp"

namespace silkworm::state {

CreateDelta::CreateDelta(evmc::address address) noexcept : address_{std::move(address)} {}

void CreateDelta::revert(IntraBlockState& state) noexcept { state.objects_.erase(address_); }

UpdateDelta::UpdateDelta(evmc::address address, state::Object previous) noexcept
    : address_{std::move(address)}, previous_{std::move(previous)} {}

void UpdateDelta::revert(IntraBlockState& state) noexcept { state.objects_[address_] = previous_; }

SuicideDelta::SuicideDelta(evmc::address address) noexcept : address_{std::move(address)} {}

void SuicideDelta::revert(IntraBlockState& state) noexcept { state.self_destructs_.erase(address_); }

TouchDelta::TouchDelta(evmc::address address) noexcept : address_{std::move(address)} {}

void TouchDelta::revert(IntraBlockState& state) noexcept { state.touched_.erase(address_); }

StorageChangeDelta::StorageChangeDelta(evmc::address address, evmc::bytes32 key, evmc::bytes32 previous) noexcept
    : address_{std::move(address)}, key_{std::move(key)}, previous_{std::move(previous)} {}

void StorageChangeDelta::revert(IntraBlockState& state) noexcept { state.storage_[address_].current[key_] = previous_; }

StorageWipeDelta::StorageWipeDelta(evmc::address address, state::Storage storage) noexcept
    : address_{std::move(address)}, storage_{std::move(storage)} {}

void StorageWipeDelta::revert(IntraBlockState& state) noexcept { state.storage_[address_] = storage_; }

StorageCreateDelta::StorageCreateDelta(evmc::address address) noexcept : address_{std::move(address)} {}

void StorageCreateDelta::revert(IntraBlockState& state) noexcept { state.storage_.erase(address_); }

StorageAccessDelta::StorageAccessDelta(evmc::address address, evmc::bytes32 key) noexcept
    : address_{std::move(address)}, key_{std::move(key)} {}

void StorageAccessDelta::revert(IntraBlockState& state) noexcept { state.accessed_storage_keys_[address_].erase(key_); }

AccountAccessDelta::AccountAccessDelta(evmc::address address) noexcept : address_{std::move(address)} {}

void AccountAccessDelta::revert(IntraBlockState& state) noexcept { state.accessed_addresses_.erase(address_); }

}  // namespace silkworm::state
