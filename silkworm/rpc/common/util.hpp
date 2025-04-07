// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <string>
#include <vector>

#include <boost/asio/buffer.hpp>
#include <ethash/keccak.hpp>
#include <evmc/evmc.hpp>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/account.hpp>
#include <silkworm/core/types/bloom.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/core/types/transaction.hpp>

namespace silkworm {

void increment(Bytes& array);

std::string base64_encode(ByteView bytes_to_encode, bool url);

bool check_tx_fee_less_cap(float cap, const intx::uint256& max_fee_per_gas, uint64_t gas_limit);

bool is_replay_protected(const Transaction& txn);

std::string decoding_result_to_string(DecodingError decode_result);

inline ByteView full_view(const Bloom& bloom) { return {bloom.data(), kBloomByteLength}; }

const ChainConfig* lookup_chain_config(uint64_t chain_id);

inline evmc::bytes32 bytes32_from_hex(const std::string& s) {
    const auto b32_bytes = from_hex(s);
    return to_bytes32(b32_bytes.value_or(silkworm::Bytes{}));
}

std::ostream& operator<<(std::ostream& out, const Account& account);

std::string get_opcode_hex(uint8_t opcode);

/// Returns the opcode name or std::nullopt if the opcode is undefined.
std::optional<std::string_view> get_opcode_name(std::uint8_t opcode) noexcept;
}  // namespace silkworm

inline auto hash_of(const silkworm::ByteView& bytes) {
    return ethash::keccak256(bytes.data(), bytes.size());
}

inline auto hash_of_transaction(const silkworm::Transaction& txn) {
    silkworm::Bytes txn_rlp{};
    silkworm::rlp::encode(txn_rlp, txn, /*wrap_eip2718_into_string=*/false);
    return ethash::keccak256(txn_rlp.data(), txn_rlp.size());
}

namespace boost::asio {

inline std::ostream& operator<<(std::ostream& out, const const_buffer& buffer) {
    out << std::string{static_cast<const char*>(buffer.data()), buffer.size()};
    return out;
}

inline std::ostream& operator<<(std::ostream& out, const std::vector<const_buffer>& buffers) {
    for (const auto buffer : buffers) {
        out << buffer;
    }
    return out;
}

}  // namespace boost::asio
