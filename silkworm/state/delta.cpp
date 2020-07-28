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

#include "delta.hpp"

#include <utility>

#include "intra_block_state.hpp"

namespace silkworm::state {

CreateDelta::CreateDelta(evmc::address address) : address_{std::move(address)} {}

void CreateDelta::revert(IntraBlockState& state) { state.objects_.erase(address_); }

UpdateDelta::UpdateDelta(evmc::address address, state::Object previous)
    : address_{std::move(address)}, previous_{std::move(previous)} {}

void UpdateDelta::revert(IntraBlockState& state) { state.objects_[address_] = previous_; }

SuicideDelta::SuicideDelta(evmc::address address) : address_{std::move(address)} {}

void SuicideDelta::revert(IntraBlockState& state) { state.self_destructs_.erase(address_); }

TouchDelta::TouchDelta(evmc::address address) : address_{std::move(address)} {}

void TouchDelta::revert(IntraBlockState& state) { state.touched_.erase(address_); }

StorageDelta::StorageDelta(evmc::address address, evmc::bytes32 key, evmc::bytes32 previous)
    : address_{std::move(address)}, key_{std::move(key)}, previous_{std::move(previous)} {}

void StorageDelta::revert(IntraBlockState& state) {
  state.storage_[address_].current[key_] = previous_;
}
}  // namespace silkworm::state
