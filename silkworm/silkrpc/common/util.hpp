/*
   Copyright 2023 The Silkworm Authors

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

#pragma once

#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include <boost/asio/buffer.hpp>
#include <ethash/keccak.hpp>
#include <evmc/evmc.hpp>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/account.hpp>
#include <silkworm/core/types/bloom.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/core/types/transaction.hpp>

namespace silkworm {

struct KeyValue {
    Bytes key;
    Bytes value;
};

inline bool operator<(const KeyValue& lhs, const KeyValue& rhs) {
    return lhs.key < rhs.key;
}

inline bool operator==(const KeyValue& lhs, const KeyValue& rhs) {
    return lhs.key == rhs.key;
}

std::string base64_encode(ByteView bytes_to_encode, bool url);

std::string to_dec(intx::uint256 number);

bool check_tx_fee_less_cap(float cap, const intx::uint256& max_fee_per_gas, uint64_t gas_limit);

bool is_replay_protected(const Transaction& txn);

std::string decoding_result_to_string(DecodingError decode_result);

template <unsigned N>
ByteView full_view(const uint8_t (&bytes)[N]) {
    return {bytes, N};
}

inline ByteView full_view(const evmc::address& address) { return {address.bytes, kAddressLength}; }

inline ByteView full_view(const evmc::bytes32& hash) { return {hash.bytes, kHashLength}; }

inline ByteView full_view(const Bloom& bloom) { return {bloom.data(), kBloomByteLength}; }

inline ByteView full_view(const ethash::hash256& hash) { return {hash.bytes, kHashLength}; }

const ChainConfig* lookup_chain_config(uint64_t chain_id);

inline std::ostream& operator<<(std::ostream& out, ByteView bytes) {
    for (const auto& b : bytes) {
        out << std::hex << std::setw(2) << std::setfill('0') << int(b);
    }
    out << std::dec;
    return out;
}

inline ByteView byte_view_of_string(const std::string& s) {
    return {reinterpret_cast<const uint8_t*>(s.data()), s.length()};
}

inline Bytes bytes_of_string(const std::string& s) {
    return {s.begin(), s.end()};
}

inline evmc::bytes32 bytes32_from_hex(const std::string& s) {
    const auto b32_bytes = from_hex(s);
    return to_bytes32(b32_bytes.value_or(silkworm::Bytes{}));
}

inline std::ostream& operator<<(std::ostream& out, const Bytes& bytes) {
    out << to_hex(bytes);
    return out;
}

std::ostream& operator<<(std::ostream& out, const Account& account);

}  // namespace silkworm

inline auto hash_of(const silkworm::ByteView& bytes) {
    return ethash::keccak256(bytes.data(), bytes.length());
}

inline auto hash_of_transaction(const silkworm::Transaction& txn) {
    silkworm::Bytes txn_rlp{};
    silkworm::rlp::encode(txn_rlp, txn, /*wrap_eip2718_into_string=*/false);
    return ethash::keccak256(txn_rlp.data(), txn_rlp.length());
}

namespace intx {
template <unsigned N>
inline std::ostream& operator<<(std::ostream& out, const uint<N>& value) {
    out << "0x" << intx::hex(value);
    return out;
}
}  // namespace intx

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
