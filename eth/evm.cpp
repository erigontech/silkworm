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

#include <algorithm>
#include <cstring>
#include <ethash/keccak.hpp>
#include <iterator>
#include <sstream>

#include "protocol_param.hpp"
#include "rlp/encode.hpp"

namespace silkworm::eth {

EVM::EVM(IntraBlockState& state, const Block& block) : state_{state}, block_{block} {}

CallResult EVM::create(const evmc::address& caller, std::string_view code, uint64_t gas,
                       const intx::uint256& value) {
  evmc_message message{
      .kind = EVMC_CREATE,
      .flags = 0,
      .depth = 0,
      .gas = static_cast<int64_t>(gas),
      .destination = {},
      .sender = caller,
      .input_data = byte_pointer_cast(code.data()),
      .input_size = code.size(),
      .value = intx::be::store<evmc::uint256be>(value),
  };

  evmc::result res = create(message);

  return {res.status_code, static_cast<uint64_t>(res.gas_left)};
}

// TODO (Andrew) propagate noexcept
evmc::result EVM::create(const evmc_message& message) noexcept {
  evmc::result res{EVMC_SUCCESS, message.gas, nullptr, 0};

  if (message.depth >= static_cast<int32_t>(param::kMaxStackDepth)) {
    res.status_code = EVMC_CALL_DEPTH_EXCEEDED;
    return res;
  }

  intx::uint256 value = intx::be::load<intx::uint256>(message.value);
  if (state_.get_balance(message.sender) < value) {
    res.status_code = static_cast<evmc_status_code>(EVMC_BALANCE_TOO_LOW);
    return res;
  }

  uint64_t nonce = state_.get_nonce(message.sender);

  evmc::address contract_addr;
  if (message.kind == EVMC_CREATE) {
    contract_addr = create_address(message.sender, nonce);
  } else if (message.kind == EVMC_CREATE2) {
    ethash::hash256 init_code_hash = ethash::keccak256(message.input_data, message.input_size);
    contract_addr = create2_address(message.sender, message.create2_salt, init_code_hash.bytes);
  }

  state_.set_nonce(message.sender, nonce + 1);

  if (state_.get_nonce(contract_addr) != 0 || state_.get_code_hash(contract_addr) != kEmptyHash) {
    // https://github.com/ethereum/EIPs/issues/684
    res.status_code = EVMC_INVALID_INSTRUCTION;
    return res;
  }

  IntraBlockState snapshot = state_;
  state_.create(contract_addr, /*contract=*/true);
  if (config_.has_spurious_dragon(block_.header.number)) {
    state_.set_nonce(contract_addr, 1);
  }

  state_.subtract_from_balance(message.sender, value);
  state_.add_to_balance(contract_addr, value);

  evmc_message deploy_message{
      .kind = EVMC_CALL,
      .flags = 0,
      .depth = message.depth,
      .gas = message.gas,
      .destination = contract_addr,
      .sender = message.sender,
      .input_data = nullptr,
      .input_size = 0,
      .value = message.value,
  };

  res = execute(deploy_message, message.input_data, message.input_size);

  if (res.status_code == EVMC_SUCCESS) {
    size_t code_len = res.output_size;
    int64_t code_deploy_gas = code_len * fee::kGcodeDeposit;

    if (config_.has_spurious_dragon(block_.header.number) && code_len > param::kMaxCodeSize) {
      // https://eips.ethereum.org/EIPS/eip-170
      res.status_code = EVMC_OUT_OF_GAS;
    } else if (res.gas_left >= code_deploy_gas) {
      res.gas_left -= code_deploy_gas;
      state_.set_code(contract_addr, {byte_pointer_cast(res.output_data), res.output_size});
    } else if (config_.has_homestead(block_.header.number)) {
      res.status_code = EVMC_OUT_OF_GAS;
    }
  }

  if (res.status_code == EVMC_SUCCESS) {
    res.create_address = contract_addr;
  } else {
    state_.revert_to_snapshot(snapshot);
    if (res.status_code != EVMC_REVERT) {
      res.gas_left = 0;
    }
  }

  return res;
}

CallResult EVM::call(const evmc::address& caller, const evmc::address& recipient,
                     std::string_view input, uint64_t gas, const intx::uint256& value) {
  evmc_message message{
      .kind = EVMC_CALL,
      .flags = 0,
      .depth = 0,
      .gas = static_cast<int64_t>(gas),
      .destination = recipient,
      .sender = caller,
      .input_data = byte_pointer_cast(input.data()),
      .input_size = input.size(),
      .value = intx::be::store<evmc::uint256be>(value),
  };

  evmc::result res = call(message);

  return {res.status_code, static_cast<uint64_t>(res.gas_left)};
}

// TODO (Andrew) propagate noexcept
evmc::result EVM::call(const evmc_message& message) noexcept {
  evmc::result res{EVMC_SUCCESS, message.gas, nullptr, 0};

  if (message.depth >= static_cast<int32_t>(param::kMaxStackDepth)) {
    res.status_code = EVMC_CALL_DEPTH_EXCEEDED;
    return res;
  }

  intx::uint256 value = intx::be::load<intx::uint256>(message.value);
  if (message.kind != EVMC_DELEGATECALL) {
    if (state_.get_balance(message.sender) < value) {
      res.status_code = static_cast<evmc_status_code>(EVMC_BALANCE_TOO_LOW);
      return res;
    }
  }

  IntraBlockState snapshot = state_;

  if (message.kind == EVMC_CALL && !(message.flags & EVMC_STATIC)) {
    if (!state_.exists(message.destination)) {
      // TODO(Andrew) precompiles

      // https://eips.ethereum.org/EIPS/eip-161
      if (config_.has_spurious_dragon(block_.header.number) && value == 0) {
        return res;
      }
      state_.create(message.destination, /*contract=*/false);
    }

    state_.subtract_from_balance(message.sender, value);
    state_.add_to_balance(message.destination, value);
  }

  std::string_view code = state_.get_code(message.destination);
  if (code.empty()) return res;

  res = execute(message, byte_pointer_cast(code.data()), code.size());

  if (res.status_code != EVMC_SUCCESS) {
    state_.revert_to_snapshot(snapshot);
    if (res.status_code != EVMC_REVERT) {
      res.gas_left = 0;
    }
  }

  return res;
}

evmc::result EVM::execute(const evmc_message& message, uint8_t const* code,
                          size_t code_size) noexcept {
  // TODO(Andrew) precompiles

  evmc_vm* evmone = evmc_create_evmone();

  EvmHost host{*this};

  return evmc::result{evmone->execute(evmone, &host.get_interface(), host.to_context(), revision(),
                                      &message, code, code_size)};
}

evmc_revision EVM::revision() const noexcept {
  uint64_t block_number = block_.header.number;

  if (config_.has_istanbul(block_number)) return EVMC_ISTANBUL;
  if (config_.has_petersburg(block_number)) return EVMC_PETERSBURG;
  if (config_.has_constantinople(block_number)) return EVMC_CONSTANTINOPLE;
  if (config_.has_byzantium(block_number)) return EVMC_BYZANTIUM;
  if (config_.has_spurious_dragon(block_number)) return EVMC_SPURIOUS_DRAGON;
  if (config_.has_tangerine_whistle(block_number)) return EVMC_TANGERINE_WHISTLE;
  if (config_.has_homestead(block_number)) return EVMC_HOMESTEAD;

  return EVMC_FRONTIER;
}

evmc::address create_address(const evmc::address& caller, uint64_t nonce) {
  std::ostringstream stream;
  rlp::Header h{.list = true, .payload_length = kAddressLength};
  h.payload_length += rlp::length(nonce);
  rlp::encode_header(stream, h);
  rlp::encode(stream, caller.bytes);
  rlp::encode(stream, nonce);
  std::string rlp = stream.str();

  ethash::hash256 hash = ethash::keccak256(byte_pointer_cast(rlp.data()), rlp.size());

  evmc::address address;
  std::memcpy(address.bytes, hash.bytes + 12, kAddressLength);
  return address;
}

evmc::address create2_address(const evmc::address& caller, const evmc::bytes32& salt,
                              uint8_t (&code_hash)[32]) noexcept {
  constexpr size_t n = 1 + kAddressLength + 2 * kHashLength;
  thread_local uint8_t buf[n];

  buf[0] = 0xff;
  std::memcpy(buf + 1, caller.bytes, kAddressLength);
  std::memcpy(buf + 1 + kAddressLength, salt.bytes, kHashLength);
  std::memcpy(buf + 1 + kAddressLength + kHashLength, code_hash, kHashLength);

  ethash::hash256 hash = ethash::keccak256(buf, n);

  evmc::address address;
  std::memcpy(address.bytes, hash.bytes + 12, kAddressLength);
  return address;
}

bool EvmHost::account_exists(const evmc::address& address) const noexcept {
  // TODO(Andrew) Do empty accounts require any special treatment (mind EIP-161)?
  return evm_.state().exists(address);
}

evmc::bytes32 EvmHost::get_storage(const evmc::address& address,
                                   const evmc::bytes32& key) const noexcept {
  return evm_.state().get_storage(address, key);
}

evmc_storage_status EvmHost::set_storage(const evmc::address& address, const evmc::bytes32& key,
                                         const evmc::bytes32& value) noexcept {
  const evmc::bytes32& prev_val = evm_.state().get_storage(address, key);

  if (prev_val == value) return EVMC_STORAGE_UNCHANGED;

  evm_.state().set_storage(address, key, value);

  if (is_zero(prev_val)) return EVMC_STORAGE_ADDED;

  if (is_zero(value)) {
    evm_.state().add_refund(fee::kRsclear);
    return EVMC_STORAGE_DELETED;
  }

  return EVMC_STORAGE_MODIFIED;

  // TODO(Andrew) EIP-2200
}

evmc::uint256be EvmHost::get_balance(const evmc::address& address) const noexcept {
  intx::uint256 balance = evm_.state().get_balance(address);
  return intx::be::store<evmc::uint256be>(balance);
}

size_t EvmHost::get_code_size(const evmc::address& address) const noexcept {
  return evm_.state().get_code(address).size();
}

evmc::bytes32 EvmHost::get_code_hash(const evmc::address& address) const noexcept {
  return evm_.state().get_code_hash(address);
}

size_t EvmHost::copy_code(const evmc::address& address, size_t code_offset, uint8_t* buffer_data,
                          size_t buffer_size) const noexcept {
  std::string_view code = evm_.state().get_code(address);

  if (code_offset >= code.size()) return 0;

  size_t n = std::min(buffer_size, code.size() - code_offset);
  std::copy_n(&code[code_offset], n, buffer_data);
  return n;
}

void EvmHost::selfdestruct(const evmc::address&, const evmc::address&) noexcept {
  // TODO(Andrew) implement
}

evmc::result EvmHost::call(const evmc_message& message) noexcept {
  if (message.kind == EVMC_CREATE || message.kind == EVMC_CREATE2) {
    return evm_.create(message);
  } else {
    return evm_.call(message);
  }
}

evmc_tx_context EvmHost::get_tx_context() const noexcept {
  evmc_tx_context context;
  // TODO (Andrew) tx_gas_price & tx_origin
  context.block_coinbase = evm_.block_.header.beneficiary;
  context.block_number = evm_.block_.header.number;
  context.block_timestamp = evm_.block_.header.timestamp;
  context.block_gas_limit = evm_.block_.header.gas_limit;
  intx::be::store(context.block_difficulty.bytes, evm_.block_.header.difficulty);
  intx::be::store(context.chain_id.bytes, intx::uint256{evm_.config_.chain_id});
  return context;
}

evmc::bytes32 EvmHost::get_block_hash(int64_t) const noexcept {
  // TODO(Andrew) implement
  return {};
}

void EvmHost::emit_log(const evmc::address& address, const uint8_t* data, size_t data_size,
                       const evmc::bytes32 topics[], size_t num_topics) noexcept {
  Log log{.address = address};
  std::copy_n(topics, num_topics, std::back_inserter(log.topics));
  std::copy_n(data, data_size, std::back_inserter(log.data));
  evm_.logs.push_back(log);
}

}  // namespace silkworm::eth
