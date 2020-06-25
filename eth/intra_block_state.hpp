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

#ifndef SILKWORM_ETH_INTRA_BLOCK_STATE_H_
#define SILKWORM_ETH_INTRA_BLOCK_STATE_H_

#include <evmc/evmc.hpp>
#include <intx/intx.hpp>
#include <string_view>

namespace silkworm::eth {

class IntraBlockState {
 public:
  IntraBlockState(const IntraBlockState&) = delete;
  IntraBlockState& operator=(const IntraBlockState&) = delete;

  IntraBlockState() = default;

  bool exists(const evmc::address& address) const;
  void create(const evmc::address& address, bool contract);

  intx::uint256 get_balance(const evmc::address& address) const;
  void add_to_balance(const evmc::address& address, const intx::uint256& addend);
  void subtract_from_balance(const evmc::address& address, const intx::uint256& subtrahend);

  uint64_t get_nonce(const evmc::address& address) const;
  void set_nonce(const evmc::address& address, uint64_t nonce);

  std::string_view get_code(const evmc::address& address) const;
  evmc::bytes32 get_code_hash(const evmc::address& address) const;

  uint64_t get_refund() const;
  void add_refund(uint64_t addend);
  void subtract_refund(uint64_t subtrahend);

  evmc::bytes32 get_storage(const evmc::address& address, const evmc::bytes32& key) const;
  void set_storage(const evmc::address& address, const evmc::bytes32& key,
                   const evmc::bytes32& value);
};

}  // namespace silkworm::eth

#endif  // SILKWORM_ETH_INTRA_BLOCK_STATE_H_
