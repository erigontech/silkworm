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

#include "evm.hpp"

#include <evmone/evmone.h>

#include <cstring>
#include <ethash/keccak.hpp>
#include <sstream>

#include "../rlp/encode.hpp"
#include "evm_host.hpp"
#include "protocol_param.hpp"

namespace silkworm::eth {

EVM::EVM(IntraBlockState& state, evmc::address coinbase, uint64_t block_number)
    : state_{state}, coinbase_{coinbase}, block_number_{block_number} {}

CreateResult EVM::create(const evmc::address& caller, std::string_view code, uint64_t gas,
                         const intx::uint256& value) {
  CreateResult res;
  res.gas_left = gas;

  if (stack_depth_ > static_cast<int32_t>(param::kMaxStackDepth)) {
    res.status = EVMC_CALL_DEPTH_EXCEEDED;
    return res;
  }

  if (state_.get_balance(caller) < value) {
    res.status = static_cast<evmc_status_code>(EVMC_BALANCE_TOO_LOW);
    return res;
  }

  uint64_t nonce = state_.get_nonce(caller);
  evmc::address contract_addr = create_address(caller, nonce);
  state_.set_nonce(caller, nonce + 1);

  if (state_.get_nonce(contract_addr) != 0 || state_.get_code_hash(contract_addr) != kEmptyHash) {
    // https://github.com/ethereum/EIPs/issues/684
    res.status = EVMC_INVALID_INSTRUCTION;
    return res;
  }

  IntraBlockState snapshot = state_;
  state_.create(contract_addr, /*contract=*/true);
  if (config_.has_spurious_dragon(block_number_)) {
    state_.set_nonce(contract_addr, 1);
  }

  state_.subtract_from_balance(caller, value);
  state_.add_to_balance(contract_addr, value);

  evmc_message message{
      .kind = EVMC_CALL,  // TODO(Andrew) shouldn't it be EVMC_CREATE?
      .flags = 0,
      .depth = stack_depth_,
      .gas = static_cast<int64_t>(gas),
      .destination = contract_addr,
      .sender = caller,
      .input_data = nullptr,
      .input_size = 0,
      .value = intx::be::store<evmc::uint256be>(value),
  };

  res = execute(message, code);

  // TODO(Andrew)
  // https://eips.ethereum.org/EIPS/eip-170

  if (res.status == EVMC_SUCCESS) {
    uint64_t code_deploy_gas = res.output.length() * fee::kGcodeDeposit;
    if (res.gas_left >= code_deploy_gas) {
      res.gas_left -= code_deploy_gas;
      state_.set_code(contract_addr, res.output);
    } else if (config_.has_homestead(block_number_)) {
      res.status = EVMC_OUT_OF_GAS;
    }
  }

  if (res.status != EVMC_SUCCESS) {
    state_.revert_to_snapshot(snapshot);
    if (res.status != EVMC_REVERT) {
      res.gas_left = 0;
    }
  }

  return res;
}

CallResult EVM::call(const evmc::address& caller, const evmc::address& recipient, std::string_view,
                     uint64_t gas, const intx::uint256& value) {
  CallResult res{.status = EVMC_SUCCESS, .gas_left = gas};

  if (stack_depth_ > static_cast<int32_t>(param::kMaxStackDepth)) {
    res.status = EVMC_CALL_DEPTH_EXCEEDED;
    return res;
  }

  if (state_.get_balance(caller) < value) {
    res.status = static_cast<evmc_status_code>(EVMC_BALANCE_TOO_LOW);
    return res;
  }

  if (!state_.exists(recipient)) {
    // TODO(Andrew) precompiles

    // https://eips.ethereum.org/EIPS/eip-161
    if (config_.has_spurious_dragon(block_number_) && value == 0) {
      return res;
    }
    state_.create(recipient, /*contract=*/false);
  }

  state_.subtract_from_balance(caller, value);
  state_.add_to_balance(recipient, value);

  // TODO(Andrew) actually run the smart contract

  return res;
}

CreateResult EVM::execute(const evmc_message& message, std::string_view code) {
  evmc_vm* evmone = evmc_create_evmone();

  EvmHost host{*this};

  ++stack_depth_;
  evmc::result evmone_res{evmone->execute(evmone, &host.get_interface(), host.to_context(),
                                          revision(), &message, byte_pointer_cast(code.data()),
                                          code.size())};
  --stack_depth_;

  CreateResult res;
  res.status = evmone_res.status_code;
  res.gas_left = evmone_res.gas_left;
  res.output = std::string{byte_pointer_cast(evmone_res.output_data), evmone_res.output_size};

  return res;
}

evmc_revision EVM::revision() const noexcept {
  if (config_.has_istanbul(block_number_)) return EVMC_ISTANBUL;
  if (config_.has_petersburg(block_number_)) return EVMC_PETERSBURG;
  if (config_.has_constantinople(block_number_)) return EVMC_CONSTANTINOPLE;
  if (config_.has_byzantium(block_number_)) return EVMC_BYZANTIUM;
  if (config_.has_spurious_dragon(block_number_)) return EVMC_SPURIOUS_DRAGON;
  if (config_.has_tangerine_whistle(block_number_)) return EVMC_TANGERINE_WHISTLE;
  if (config_.has_homestead(block_number_)) return EVMC_HOMESTEAD;

  return EVMC_FRONTIER;
}

evmc::address create_address(const evmc::address& caller, uint64_t nonce) {
  std::ostringstream stream;
  rlp::Header h{.list = true, .length = kAddressLength};
  h.length += rlp::length(nonce);
  rlp::encode(stream, h);
  rlp::encode(stream, caller.bytes);
  rlp::encode(stream, nonce);
  std::string rlp = stream.str();

  ethash::hash256 hash = ethash::keccak256(byte_pointer_cast(rlp.data()), rlp.size());

  evmc::address address;
  std::memcpy(address.bytes, hash.bytes + 12, kAddressLength);
  return address;
}

evmc::address create2_address(const evmc::address& caller, const evmc::bytes32& salt,
                              const evmc::bytes32& code_hash) {
  constexpr size_t n = 1 + kAddressLength + 2 * kHashLength;
  thread_local uint8_t buf[n];

  buf[0] = 0xff;
  std::memcpy(buf + 1, caller.bytes, kAddressLength);
  std::memcpy(buf + 1 + kAddressLength, salt.bytes, kHashLength);
  std::memcpy(buf + 1 + kAddressLength + kHashLength, code_hash.bytes, kHashLength);

  ethash::hash256 hash = ethash::keccak256(buf, n);

  evmc::address address;
  std::memcpy(address.bytes, hash.bytes + 12, kAddressLength);
  return address;
}

}  // namespace silkworm::eth
