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

#include <evmc/evmc.hpp>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/types/hash.hpp>

namespace intx {
template <unsigned N>
inline std::ostream& operator<<(std::ostream& out, const uint<N>& value) {
    out << "0x" << intx::hex(value);
    return out;
}
}  // namespace intx

namespace silkworm {

template <unsigned N>
ByteView full_view(const uint8_t (&bytes)[N]) {
    return {bytes, N};
}

inline ByteView full_view(const evmc::address& address) { return {address.bytes, kAddressLength}; }

inline ByteView full_view(const evmc::bytes32& hash) { return {hash.bytes, kHashLength}; }

inline ByteView full_view(const ethash::hash256& hash) { return {hash.bytes, kHashLength}; }

inline ByteView byte_view_of_string(const std::string& s) {
    return {reinterpret_cast<const uint8_t*>(s.data()), s.length()};
}

inline Bytes bytes_of_string(const std::string& s) {
    return {s.begin(), s.end()};
}

inline std::ostream& operator<<(std::ostream& out, ByteView bytes) {
    for (const auto& b : bytes) {
        out << std::hex << std::setw(2) << std::setfill('0') << int(b);
    }
    out << std::dec;
    return out;
}

inline std::ostream& operator<<(std::ostream& out, const Bytes& bytes) {
    out << to_hex(bytes);
    return out;
}

}  // namespace silkworm

namespace silkworm::db::kv::api {

Bytes composite_storage_key(const evmc::address& address, uint64_t incarnation, HashAsArray hash);

}  // namespace silkworm::db::kv::api
