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

IntraBlockState::Object* IntraBlockState::get_object(const evmc::address& address) const {
  auto it{objects_.find(address)};
  if (it != objects_.end()) return &it->second;

  if (!db_) return nullptr;

  std::optional<Account> account{db_->read_account(address)};
  if (!account) return nullptr;

  Object& obj{objects_[address]};
  obj.original = *account;
  obj.current = *account;
  return &obj;
}

IntraBlockState::Object& IntraBlockState::get_or_create_object(const evmc::address& address) {
  Object* obj{get_object(address)};
  if (!obj) {
    obj = &objects_[address];
  }
  if (!obj->current) {
    obj->current = Account{};
  }
  return *obj;
}

bool IntraBlockState::exists(const evmc::address& address) const {
  Object* obj{get_object(address)};
  return obj && obj->current;
}

bool IntraBlockState::dead(const evmc::address& address) const {
  Object* obj{get_object(address)};
  if (!obj || !obj->current) {
    return true;
  }
  return obj->current->code_hash == kEmptyHash && obj->current->nonce == 0 &&
         obj->current->balance == 0;
}

void IntraBlockState::create_contract(const evmc::address& address) {
  Object created{};
  created.current = Account{};

  std::optional<uint64_t> prev_incarnation{};
  Object* prev{get_object(address)};
  if (prev) {
    created.original = prev->original;
    if (prev->current) {
      created.current->balance = prev->current->balance;
      prev_incarnation = prev->current->incarnation;
    } else if (prev->original) {
      prev_incarnation = prev->original->incarnation;
    }
  }

  if (!prev_incarnation) {
    // TODO[Constantinople] read previous incarnation from the DB instead
    prev_incarnation = 0;
  }

  created.current->incarnation = *prev_incarnation + 1;

  objects_[address] = created;
}

void IntraBlockState::record_suicide(const evmc::address& address) {
  self_destructs_.insert(address);
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

void IntraBlockState::destruct(const evmc::address& address) {
  Object* obj{get_object(address)};
  if (!obj) return;
  obj->current.reset();
  obj->current_storage.clear();
  obj->code.reset();
}

intx::uint256 IntraBlockState::get_balance(const evmc::address& address) const {
  Object* obj{get_object(address)};
  return obj && obj->current ? obj->current->balance : 0;
}

void IntraBlockState::set_balance(const evmc::address& address, const intx::uint256& value) {
  get_or_create_object(address).current->balance = value;
  touched_.insert(address);
}

void IntraBlockState::add_to_balance(const evmc::address& address, const intx::uint256& addend) {
  get_or_create_object(address).current->balance += addend;
  touched_.insert(address);
}

void IntraBlockState::subtract_from_balance(const evmc::address& address,
                                            const intx::uint256& subtrahend) {
  get_or_create_object(address).current->balance -= subtrahend;
  touched_.insert(address);
}

uint64_t IntraBlockState::get_nonce(const evmc::address& address) const {
  Object* obj{get_object(address)};
  return obj && obj->current ? obj->current->nonce : 0;
}

void IntraBlockState::set_nonce(const evmc::address& address, uint64_t nonce) {
  get_or_create_object(address).current->nonce = nonce;
}

ByteView IntraBlockState::get_code(const evmc::address& address) const {
  Object* obj{get_object(address)};

  if (!obj || !obj->current || obj->current->code_hash == kEmptyHash) return {};
  if (obj->code) return *obj->code;

  if (!db_) return {};
  obj->code = db_->read_code(obj->current->code_hash);

  return *obj->code;
}

evmc::bytes32 IntraBlockState::get_code_hash(const evmc::address& address) const {
  Object* obj{get_object(address)};
  return obj && obj->current ? obj->current->code_hash : kEmptyHash;
}

void IntraBlockState::set_code(const evmc::address& address, ByteView code) {
  Object& obj{get_or_create_object(address)};
  obj.code = code;
  ethash::hash256 hash{ethash::keccak256(code.data(), code.size())};
  std::memcpy(obj.current->code_hash.bytes, hash.bytes, kHashLength);
}

evmc::bytes32 IntraBlockState::get_storage(const evmc::address& address,
                                           const evmc::bytes32& key) const {
  Object* obj{get_object(address)};
  if (!obj || !obj->current) return {};

  auto it{obj->current_storage.find(key)};
  if (it != obj->current_storage.end()) return it->second;

  uint64_t incarnation{obj->current->incarnation};

  if (!obj->original || obj->original->incarnation != incarnation) return {};
  it = obj->original_storage.find(key);
  if (it != obj->original_storage.end()) return it->second;

  evmc::bytes32 val{};
  if (db_) val = db_->read_storage(address, incarnation, key);

  obj->original_storage[key] = val;
  return val;
}

void IntraBlockState::set_storage(const evmc::address& address, const evmc::bytes32& key,
                                  const evmc::bytes32& value) {
  evmc::bytes32 prev{get_storage(address, key)};
  if (prev == value) return;
  get_or_create_object(address).current_storage[key] = value;
}

void IntraBlockState::write_block(state::Writer& state_writer) {
  for (const auto& entry : objects_) {
    const evmc::address& address{entry.first};
    const Object& obj{entry.second};

    for (const auto& storage_entry : obj.current_storage) {
      const evmc::bytes32& key{storage_entry.first};
      uint64_t incarnation{obj.current->incarnation};
      evmc::bytes32 original_val{};
      if (obj.original && obj.original->incarnation == incarnation) {
        auto it = obj.original_storage.find(key);
        if (it != obj.original_storage.end()) original_val = it->second;
      }
      state_writer.write_storage(address, incarnation, key, original_val, storage_entry.second);
    }

    state_writer.write_account(address, obj.original, obj.current);
  }
}

void IntraBlockState::clear_substate() {
  self_destructs_.clear();
  logs_.clear();
  touched_.clear();
  refund_ = 0;
}

void IntraBlockState::add_log(const Log& log) { logs_.push_back(log); }

void IntraBlockState::add_refund(uint64_t addend) { refund_ += addend; }

uint64_t IntraBlockState::total_refund() const {
  return refund_ + fee::kRSelfDestruct * self_destructs_.size();
}
}  // namespace silkworm
