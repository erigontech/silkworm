/*
   Copyright 2022 The Silkworm Authors

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

#include "address.hpp"

#include <ethash/keccak.hpp>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/rlp/encode.hpp>

namespace silkworm {

namespace rlp {

    void encode(Bytes& to, const evmc::address& address) {
        encode(to, ByteView{address.bytes});
    }

    DecodingResult decode(ByteView& from, evmc::address& address, Leftover mode) {
        SILKWORM_ASSERT(from.size() >= std::size(address.bytes));
        return decode(from, address.bytes, mode);
    }

    size_t length(const evmc::address& address) noexcept {
        return length(ByteView{address.bytes});
    }

}  // namespace rlp

evmc::address create_address(const evmc::address& caller, uint64_t nonce) noexcept {
    rlp::Header h{true, 1 + kAddressLength};
    h.payload_length += rlp::length(nonce);

    Bytes rlp{};
    rlp::encode_header(rlp, h);
    rlp::encode(rlp, caller);
    rlp::encode(rlp, nonce);

    ethash::hash256 hash{keccak256(rlp)};

    evmc::address address{};
    std::memcpy(address.bytes, hash.bytes + 12, kAddressLength);
    return address;
}

evmc::address create2_address(const evmc::address& caller, const evmc::bytes32& salt,
                              uint8_t (&code_hash)[32]) noexcept {
    static constexpr size_t kN{1 + kAddressLength + 2 * kHashLength};
    uint8_t buf[kN];

    buf[0] = 0xff;
    std::memcpy(buf + 1, caller.bytes, kAddressLength);
    std::memcpy(buf + 1 + kAddressLength, salt.bytes, kHashLength);
    std::memcpy(buf + 1 + kAddressLength + kHashLength, code_hash, kHashLength);

    ethash::hash256 hash{ethash::keccak256(buf, kN)};

    evmc::address address{};
    std::memcpy(address.bytes, hash.bytes + 12, kAddressLength);
    return address;
}

evmc::address bytes_to_address(ByteView bytes) {
    evmc::address out;
    if (!bytes.empty()) {
        size_t n{std::min(bytes.size(), kAddressLength)};
        std::memcpy(out.bytes + kAddressLength - n, bytes.data(), n);
    }
    return out;
}

evmc::address hex_to_address(std::string_view hex, bool return_zero_on_err) {
    const std::optional<Bytes> bytes{from_hex(hex)};
    if (!bytes) {
        if (return_zero_on_err) {
            return evmc::address{};
        }
        abort_due_to_assertion_failure("invalid hex encoding", __FILE__, __LINE__);
    }
    return bytes_to_address(*bytes);
}

std::string address_to_hex(const evmc::address& address) {
    return to_hex(ByteView{address.bytes}, true);
}

}  // namespace silkworm

namespace evmc {

std::ostream& operator<<(std::ostream& out, const evmc::address& address) {
    return out << silkworm::address_to_hex(address);
}

}  // namespace evmc
