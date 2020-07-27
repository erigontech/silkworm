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

#include <absl/container/flat_hash_map.h>
#include <absl/container/flat_hash_set.h>

#include <evmc/evmc.hpp>
#include <intx/intx.hpp>
#include <optional>
#include <silkworm/common/base.hpp>
#include <silkworm/state/reader.hpp>
#include <silkworm/state/writer.hpp>
#include <silkworm/types/account.hpp>
#include <silkworm/types/log.hpp>
#include <vector>

namespace silkworm {

class IntraBlockState {
 public:
  IntraBlockState(const IntraBlockState&) = default;
  IntraBlockState& operator=(const IntraBlockState&) = default;

  explicit IntraBlockState(state::Reader* state_reader) : db_{state_reader} {}

  bool exists(const evmc::address& address) const;

  // https://eips.ethereum.org/EIPS/eip-161
  bool dead(const evmc::address& address) const;

  void create_contract(const evmc::address& address);

  void record_suicide(const evmc::address& address);
  void destruct_suicides();
  void destruct_touched_dead();

  intx::uint256 get_balance(const evmc::address& address) const;
  void set_balance(const evmc::address& address, const intx::uint256& value);
  void add_to_balance(const evmc::address& address, const intx::uint256& addend);
  void subtract_from_balance(const evmc::address& address, const intx::uint256& subtrahend);

  uint64_t get_nonce(const evmc::address& address) const;
  void set_nonce(const evmc::address& address, uint64_t nonce);

  ByteView get_code(const evmc::address& address) const;
  evmc::bytes32 get_code_hash(const evmc::address& address) const;
  void set_code(const evmc::address& address, ByteView code);

  evmc::bytes32 get_storage(const evmc::address& address, const evmc::bytes32& key) const;
  void set_storage(const evmc::address& address, const evmc::bytes32& key,
                   const evmc::bytes32& value);

  void write_block(state::Writer& state_writer);

  // See Section 6.1 "Substate" of the Yellow Paper
  void clear_substate();

  void add_log(const Log& log);

  const std::vector<Log>& logs() const { return logs_; }

  void add_refund(uint64_t addend);

  uint64_t total_refund() const;

 private:
  using Storage = absl::flat_hash_map<evmc::bytes32, evmc::bytes32>;

  struct Object {
    std::optional<Account> original;
    std::optional<Account> current;
    Storage original_storage;
    Storage current_storage;
    std::optional<Bytes> code;
  };

  Object* get_object(const evmc::address& address) const;
  Object& get_or_create_object(const evmc::address& address);

  void destruct(const evmc::address& address);

  state::Reader* db_{nullptr};

  mutable absl::flat_hash_map<evmc::address, Object> objects_;

  // substate
  absl::flat_hash_set<evmc::address> self_destructs_;
  std::vector<Log> logs_;
  absl::flat_hash_set<evmc::address> touched_;
  uint64_t refund_{0};
};
}  // namespace silkworm

#endif  // SILKWORM_STATE_INTRA_BLOCK_STATE_H_
