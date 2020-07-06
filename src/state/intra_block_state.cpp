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

namespace silkworm {

IntraBlockState::Object* IntraBlockState::get_object(const evmc::address& address) const {
  auto it = objects_.find(address);
  if (it != objects_.end()) return &it->second;

  std::optional<Account> account = db_.read_account(address);
  if (!account) return nullptr;

  Object& obj = objects_[address];
  obj.original = *account;
  obj.current = *account;
  return &obj;
}

IntraBlockState::Object& IntraBlockState::get_or_create_object(const evmc::address& address) {
  Object* obj = get_object(address);
  if (!obj) {
    Object& new_obj = objects_[address];
    new_obj.current = Account{};
    return new_obj;
  }
  if (!obj->current) {
    obj->current = Account{};
  }
  return *obj;
}

bool IntraBlockState::exists(const evmc::address& address) const {
  Object* obj = get_object(address);
  return obj && obj->current;
}

void IntraBlockState::create_contract(const evmc::address& address) {
  Object created;
  created.current = Account{};

  std::optional<uint64_t> prev_incarnation;
  Object* prev = get_object(address);
  if (prev) {
    created.original = prev->original;
    if (prev->current) {
      created.current->balance = prev->current->balance;
      prev_incarnation = prev->current->incarnation;
    } else if (prev->original) {
      prev_incarnation = prev->original->incarnation;
    }
  }

  if (prev_incarnation) {
    created.current->incarnation = *prev_incarnation + 1;
  } else {
    created.current->incarnation = 1;
  }

  objects_[address] = created;
}

intx::uint256 IntraBlockState::get_balance(const evmc::address& address) const {
  Object* obj = get_object(address);
  return obj && obj->current ? obj->current->balance : 0;
}

void IntraBlockState::add_to_balance(const evmc::address& address, const intx::uint256& addend) {
  get_or_create_object(address).current->balance += addend;
}

void IntraBlockState::subtract_from_balance(const evmc::address& address,
                                            const intx::uint256& subtrahend) {
  get_or_create_object(address).current->balance -= subtrahend;
}

uint64_t IntraBlockState::get_nonce(const evmc::address& address) const {
  Object* obj = get_object(address);
  return obj && obj->current ? obj->current->nonce : 0;
}

void IntraBlockState::set_nonce(const evmc::address& address, uint64_t nonce) {
  get_or_create_object(address).current->nonce = nonce;
}

std::string_view IntraBlockState::get_code(const evmc::address& address) const {
  Object* obj = get_object(address);
  if (!obj || !obj->current) return {};
  if (obj->code) return *obj->code;
  if (obj->current->code_hash == kEmptyHash) return {};

  obj->code = db_.read_account_code(address);
  return *obj->code;
}

evmc::bytes32 IntraBlockState::get_code_hash(const evmc::address& address) const {
  Object* obj = get_object(address);
  return obj && obj->current ? obj->current->code_hash : kEmptyHash;
}

void IntraBlockState::set_code(const evmc::address& address, std::string_view code) {
  Object& obj = get_or_create_object(address);
  obj.code = code;
  ethash::hash256 hash = ethash::keccak256(byte_pointer_cast(code.data()), code.size());
  std::memcpy(obj.current->code_hash.bytes, hash.bytes, kHashLength);
}

evmc::bytes32 IntraBlockState::get_storage(const evmc::address& address,
                                           const evmc::bytes32& key) const {
  Object* obj = get_object(address);
  if (!obj || !obj->current) return {};

  auto it = obj->current_storage.find(key);
  if (it != obj->current_storage.end()) return it->second;

  uint64_t incarnation = obj->current->incarnation;
  if (!obj->original || obj->original->incarnation != incarnation) {
    return {};
  }

  it = obj->original_storage.find(key);
  if (it != obj->original_storage.end()) return it->second;

  evmc::bytes32 val = db_.read_account_storage(address, incarnation, key);
  obj->original_storage[key] = val;
  return val;
}

void IntraBlockState::set_storage(const evmc::address& address, const evmc::bytes32& key,
                                  const evmc::bytes32& value) {
  get_or_create_object(address).current_storage[key] = value;
}

int IntraBlockState::take_snapshot() const {
  // TODO(Andrew) implement
  return 0;
}

void IntraBlockState::revert_to_snapshot(int) {
  // TODO(Andrew) implement
}

}  // namespace silkworm
