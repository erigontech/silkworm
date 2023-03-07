/*
   Copyright 2020 The Silkrpc Authors

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

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/transaction.hpp>
#include <silkworm/core/types/account.hpp>
#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/types/bloom.hpp>

namespace silkrpc {

struct KeyValue {
    silkworm::Bytes key;
    silkworm::Bytes value;
};

inline bool operator<(const KeyValue& lhs, const KeyValue& rhs) {
    return lhs.key < rhs.key;
}

inline bool operator==(const KeyValue& lhs, const KeyValue& rhs) {
    return lhs.key == rhs.key;
}

std::string base64_encode(const uint8_t* bytes_to_encode, size_t len, bool url);

std::string to_dec(intx::uint256 number);

bool check_tx_fee_less_cap(float cap, intx::uint256 max_fee_per_gas, uint64_t gas_limit);

bool is_replay_protected(const silkworm::Transaction& txn);

std::string decoding_result_to_string(silkworm::DecodingError decode_result);

template <unsigned N>
silkworm::ByteView full_view(const uint8_t (&bytes)[N]) {
    return {bytes, N};
}

inline silkworm::ByteView full_view(const evmc::address& address) { return {address.bytes, silkworm::kAddressLength}; }

inline silkworm::ByteView full_view(const evmc::bytes32& hash) { return {hash.bytes, silkworm::kHashLength}; }

inline silkworm::ByteView full_view(const silkworm::Bloom& bloom) { return {bloom.data(), silkworm::kBloomByteLength}; }

inline silkworm::ByteView full_view(const ethash::hash256& hash) { return {hash.bytes, silkworm::kHashLength}; }

const silkworm::ChainConfig* lookup_chain_config(uint64_t chain_id);

} // namespace silkrpc

namespace silkworm {

inline ByteView byte_view_of_string(const std::string& s) {
    return {reinterpret_cast<const uint8_t*>(s.data()), s.length()};
}

inline Bytes bytes_of_string(const std::string& s) {
    return Bytes(s.begin(), s.end());
}

inline evmc::bytes32 bytes32_from_hex(const std::string& s) {
    const auto b32_bytes = silkworm::from_hex(s);
    return silkworm::to_bytes32(b32_bytes.value_or(silkworm::Bytes{}));
}

inline std::ostream& operator<<(std::ostream& out, const Bytes& bytes) {
    out << silkworm::to_hex(bytes);
    return out;
}

std::ostream& operator<<(std::ostream& out, const Account& account);

} // namespace silkworm

inline auto hash_of(const silkworm::ByteView& bytes) {
    return ethash::keccak256(bytes.data(), bytes.length());
}

inline auto hash_of_transaction(const silkworm::Transaction& txn) {
    silkworm::Bytes txn_rlp{};
    silkworm::rlp::encode(txn_rlp, txn, /*for_signing=*/false, /*wrap_eip2718_as_array=*/false);
    return ethash::keccak256(txn_rlp.data(), txn_rlp.length());
}

inline std::ostream& operator<<(std::ostream& out, const silkworm::ByteView& bytes) {
    for (const auto& b : bytes) {
        out << std::hex << std::setw(2) << std::setfill('0') << int(b);
    }
    out << std::dec;
    return out;
}

namespace evmc {

inline std::ostream& operator<<(std::ostream& out, const address& addr) {
    out << silkworm::to_hex(addr);
    return out;
}

inline std::ostream& operator<<(std::ostream& out, const bytes32& b32) {
    out << silkworm::to_hex(b32);
    return out;
}

} // namespace evmc

namespace intx {
template <unsigned N>
inline std::ostream& operator<<(std::ostream& out, const uint<N>& value) {
    out << "0x" << intx::hex(value);
    return out;
}
} // namespace intx

inline std::ostream& operator<<(std::ostream& out, const boost::asio::const_buffer& buffer) {
    out << std::string{static_cast<const char*>(buffer.data()), buffer.size()};
    return out;
}

inline std::ostream& operator<<(std::ostream& out, const std::vector<boost::asio::const_buffer>& buffers) {
    for (const auto buffer : buffers) {
        out << buffer;
    }
    return out;
}

