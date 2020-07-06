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

#ifndef SILKWORM_STATE_INTRA_BLOCK_STATE_H_
#define SILKWORM_STATE_INTRA_BLOCK_STATE_H_

#include <evmc/evmc.hpp>
#include <intx/intx.hpp>
#include <map>
#include <optional>
#include <string>
#include <string_view>

#include "reader.hpp"
#include "types/account.hpp"

namespace silkworm {

class IntraBlockState {
 public:
  IntraBlockState(const IntraBlockState&) = delete;
  IntraBlockState& operator=(const IntraBlockState&) = delete;

  explicit IntraBlockState(state::Reader& state_reader) : db_{state_reader} {}

  bool exists(const evmc::address& address) const;
  void create_contract(const evmc::address& address);

  intx::uint256 get_balance(const evmc::address& address) const;
  void add_to_balance(const evmc::address& address, const intx::uint256& addend);
  void subtract_from_balance(const evmc::address& address, const intx::uint256& subtrahend);

  uint64_t get_nonce(const evmc::address& address) const;
  void set_nonce(const evmc::address& address, uint64_t nonce);

  std::string_view get_code(const evmc::address& address) const;
  evmc::bytes32 get_code_hash(const evmc::address& address) const;
  void set_code(const evmc::address& address, std::string_view code);

  evmc::bytes32 get_storage(const evmc::address& address, const evmc::bytes32& key) const;
  void set_storage(const evmc::address& address, const evmc::bytes32& key,
                   const evmc::bytes32& value);

  int take_snapshot() const;
  void revert_to_snapshot(int snapshot);

 private:
  using Storage = std::map<evmc::bytes32, evmc::bytes32>;

  struct Object {
    std::optional<Account> original;
    std::optional<Account> current;
    Storage original_storage;
    Storage current_storage;
    std::optional<std::string> code;
  };

  Object* get_object(const evmc::address& address) const;
  Object& get_or_create_object(const evmc::address& address);

  state::Reader& db_;
  mutable std::map<evmc::address, Object> objects_;
};
}  // namespace silkworm

#endif  // SILKWORM_STATE_INTRA_BLOCK_STATE_H_
