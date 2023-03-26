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

#include "conversion.hpp"

// operator== overloading is *NOT* present in gRPC generated sources
namespace types {

bool operator==(const H512& lhs, const H512& rhs) {
    return lhs.hi() == rhs.hi() && lhs.lo() == rhs.lo();
}

bool operator==(const H256& lhs, const H256& rhs) {
    return lhs.hi() == rhs.hi() && lhs.lo() == rhs.lo();
}

bool operator==(const H160& lhs, const H160& rhs) {
    return lhs.hi() == rhs.hi() && lhs.lo() == rhs.lo();
}

bool operator==(const H128& lhs, const H128& rhs) {
    return lhs.hi() == rhs.hi() && lhs.lo() == rhs.lo();
}

}  // namespace types

namespace silkworm::rpc {

constexpr uint64_t lo_lo(const intx::uint256& x) { return x[0]; }
constexpr uint64_t lo_hi(const intx::uint256& x) { return x[1]; }
constexpr uint64_t hi_lo(const intx::uint256& x) { return x[2]; }
constexpr uint64_t hi_hi(const intx::uint256& x) { return x[3]; }

std::string string_from_H512(const types::H512& orig) {
    uint64_t hi_hi_hi = orig.hi().hi().hi();
    uint64_t hi_hi_lo = orig.hi().hi().lo();
    uint64_t hi_lo_hi = orig.hi().lo().hi();
    uint64_t hi_lo_lo = orig.hi().lo().lo();
    uint64_t lo_hi_hi = orig.lo().hi().hi();
    uint64_t lo_hi_lo = orig.lo().hi().lo();
    uint64_t lo_lo_hi = orig.lo().lo().hi();
    uint64_t lo_lo_lo = orig.lo().lo().lo();

    std::string dest(64, 0);
    auto data = reinterpret_cast<uint8_t*>(dest.data());
    endian::store_big_u64(data + 0, hi_hi_hi);
    endian::store_big_u64(data + 8, hi_hi_lo);
    endian::store_big_u64(data + 16, hi_lo_hi);
    endian::store_big_u64(data + 24, hi_lo_lo);
    endian::store_big_u64(data + 32, lo_hi_hi);
    endian::store_big_u64(data + 40, lo_hi_lo);
    endian::store_big_u64(data + 48, lo_lo_hi);
    endian::store_big_u64(data + 56, lo_lo_lo);

    return dest;
}

std::string string_from_H2048(const types::H2048& orig) {
    const auto& hi_hi = orig.hi().hi();
    const auto& hi_lo = orig.hi().lo();
    const auto& lo_hi = orig.lo().hi();
    const auto& lo_lo = orig.lo().lo();

    std::string dest(256, 0);
    dest.append(string_from_H512(hi_hi));
    dest.append(string_from_H512(hi_lo));
    dest.append(string_from_H512(lo_hi));
    dest.append(string_from_H512(lo_lo));
    return dest;
}

evmc::bytes32 bytes32_from_H256(const types::H256& orig) {
    uint64_t hi_hi = orig.hi().hi();
    uint64_t hi_lo = orig.hi().lo();
    uint64_t lo_hi = orig.lo().hi();
    uint64_t lo_lo = orig.lo().lo();

    evmc::bytes32 dest;
    endian::store_big_u64(dest.bytes + 0, hi_hi);
    endian::store_big_u64(dest.bytes + 8, hi_lo);
    endian::store_big_u64(dest.bytes + 16, lo_hi);
    endian::store_big_u64(dest.bytes + 24, lo_lo);

    return dest;
}

intx::uint256 uint256_from_H256(const types::H256& orig) {
    uint64_t hi_hi = orig.hi().hi();
    uint64_t hi_lo = orig.hi().lo();
    uint64_t lo_hi = orig.lo().hi();
    uint64_t lo_lo = orig.lo().lo();

    return {lo_lo, lo_hi, hi_lo, hi_hi};
}

evmc::address address_from_H160(const types::H160& orig) {
    uint64_t hi_hi = orig.hi().hi();
    uint64_t hi_lo = orig.hi().lo();
    uint32_t lo = orig.lo();

    evmc::address dest;
    endian::store_big_u64(dest.bytes + 0, hi_hi);
    endian::store_big_u64(dest.bytes + 8, hi_lo);
    endian::store_big_u32(dest.bytes + 16, lo);

    return dest;
}

std::unique_ptr<types::H512> H512_from_string(std::string_view orig) {
    Bytes bytes(64, 0);
    uint8_t* data = bytes.data();
    std::memcpy(data, orig.data(), orig.length() < 64 ? orig.length() : 64);

    auto hi_hi = new types::H128{};
    auto hi_lo = new types::H128{};
    auto lo_hi = new types::H128{};
    auto lo_lo = new types::H128{};
    hi_hi->set_hi(endian::load_big_u64(data + 0));
    hi_hi->set_lo(endian::load_big_u64(data + 8));
    hi_lo->set_hi(endian::load_big_u64(data + 16));
    hi_lo->set_lo(endian::load_big_u64(data + 24));
    lo_hi->set_hi(endian::load_big_u64(data + 32));
    lo_hi->set_lo(endian::load_big_u64(data + 40));
    lo_lo->set_hi(endian::load_big_u64(data + 48));
    lo_lo->set_lo(endian::load_big_u64(data + 56));

    auto hi = new types::H256{};
    auto lo = new types::H256{};
    hi->set_allocated_hi(hi_hi);  // takes ownership
    hi->set_allocated_lo(hi_lo);  // takes ownership
    lo->set_allocated_hi(lo_hi);  // takes ownership
    lo->set_allocated_lo(lo_lo);  // takes ownership

    auto dest = std::make_unique<types::H512>();
    dest->set_allocated_hi(hi);  // takes ownership
    dest->set_allocated_lo(lo);  // takes ownership

    return dest;
}

std::unique_ptr<types::H256> H256_from_bytes32(const evmc::bytes32& orig) {
    auto hi = new types::H128{};
    auto lo = new types::H128{};
    hi->set_hi(endian::load_big_u64(orig.bytes + 0));
    hi->set_lo(endian::load_big_u64(orig.bytes + 8));
    lo->set_hi(endian::load_big_u64(orig.bytes + 16));
    lo->set_lo(endian::load_big_u64(orig.bytes + 24));

    auto dest = std::make_unique<types::H256>();
    dest->set_allocated_hi(hi);  // takes ownership
    dest->set_allocated_lo(lo);  // takes ownership

    return dest;
}

std::unique_ptr<types::H256> H256_from_uint256(const intx::uint256& orig) {
    auto dest = std::make_unique<types::H256>();

    auto hi = new types::H128{};
    auto lo = new types::H128{};

    hi->set_hi(hi_hi(orig));
    hi->set_lo(hi_lo(orig));
    lo->set_hi(lo_hi(orig));
    lo->set_lo(lo_lo(orig));

    dest->set_allocated_hi(hi);  // take ownership
    dest->set_allocated_lo(lo);  // take ownership

    return dest;  // transfer ownership
}

std::unique_ptr<types::H160> H160_from_address(const evmc::address& orig) {
    auto hi = new types::H128{};
    hi->set_hi(endian::load_big_u64(orig.bytes));
    hi->set_lo(endian::load_big_u64(orig.bytes + 8));

    auto dest = std::make_unique<types::H160>();
    dest->set_allocated_hi(hi);  // takes ownership
    dest->set_lo(endian::load_big_u32(orig.bytes + 16));

    return dest;
}

std::unique_ptr<types::H2048> H2048_from_string(std::string_view orig) {
    auto lo_lo = H512_from_string(orig);
    auto lo_hi = H512_from_string(orig.substr(512));
    auto hi_lo = H512_from_string(orig.substr(1024));
    auto hi_hi = H512_from_string(orig.substr(1536));

    auto hi = new types::H1024{};
    auto lo = new types::H1024{};

    hi->set_allocated_hi(hi_hi.release());
    hi->set_allocated_lo(hi_lo.release());
    lo->set_allocated_hi(lo_hi.release());
    lo->set_allocated_lo(lo_lo.release());

    auto dest = std::make_unique<types::H2048>();
    dest->set_allocated_hi(hi);  // takes ownership
    dest->set_allocated_lo(lo);  // takes ownership

    return dest;
}

}  // namespace silkworm::rpc
