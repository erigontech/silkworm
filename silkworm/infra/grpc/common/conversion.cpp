// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "conversion.hpp"

// operator== overloading is *NOT* present in gRPC generated sources
namespace types {

bool operator==(const H2048& lhs, const H2048& rhs) {
    return lhs.hi() == rhs.hi() && lhs.lo() == rhs.lo();
}

bool operator==(const H1024& lhs, const H1024& rhs) {
    return lhs.hi() == rhs.hi() && lhs.lo() == rhs.lo();
}

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

std::string string_from_h2048(const ::types::H2048& orig) {
    const auto& hi_hi = orig.hi().hi();
    const auto& hi_lo = orig.hi().lo();
    const auto& lo_hi = orig.lo().hi();
    const auto& lo_lo = orig.lo().lo();

    std::string dest(256, 0);
    dest.append(string_from_h512(hi_hi));
    dest.append(string_from_h512(hi_lo));
    dest.append(string_from_h512(lo_hi));
    dest.append(string_from_h512(lo_lo));
    return dest;
}

Bytes bytes_from_h2048(const ::types::H2048& h2048) {
    Bytes bytes(256, '\0');
    const auto& hi{h2048.hi()};
    const auto& lo{h2048.lo()};
    std::memcpy(&bytes[0], bytes_from_h1024(hi).data(), 128);
    std::memcpy(&bytes[128], bytes_from_h1024(lo).data(), 128);
    return bytes;
}

void span_from_h2048(const ::types::H2048& h2048, ByteSpan<256> bytes) {
    const auto& hi{h2048.hi()};
    const auto& lo{h2048.lo()};
    span_from_h1024(hi, bytes.subspan<0, 128>());
    span_from_h1024(lo, bytes.subspan<128, 128>());
}

Bytes bytes_from_h1024(const ::types::H1024& h1024) {
    Bytes bytes(128, '\0');
    const auto& hi{h1024.hi()};
    const auto& lo{h1024.lo()};
    std::memcpy(&bytes[0], bytes_from_h512(hi).data(), 64);
    std::memcpy(&bytes[64], bytes_from_h512(lo).data(), 64);
    return bytes;
}

void span_from_h1024(const ::types::H1024& h1024, ByteSpan<128> bytes) {
    const auto& hi{h1024.hi()};
    const auto& lo{h1024.lo()};
    span_from_h512(hi, bytes.subspan<0, 64>());
    span_from_h512(lo, bytes.subspan<64, 64>());
}

std::string string_from_h512(const types::H512& orig) {
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

Bytes bytes_from_h512(const ::types::H512& h512) {
    Bytes bytes(64, '\0');
    const auto& hi{h512.hi()};
    const auto& lo{h512.lo()};
    std::memcpy(&bytes[0], bytes_from_h256(hi).data(), 32);
    std::memcpy(&bytes[32], bytes_from_h256(lo).data(), 32);
    return bytes;
}

void span_from_h512(const ::types::H512& h512, ByteSpan<64> bytes) {
    const auto& hi{h512.hi()};
    const auto& lo{h512.lo()};
    span_from_h256(hi, bytes.subspan<0, 32>());
    span_from_h256(lo, bytes.subspan<32, 32>());
}

evmc::bytes32 bytes32_from_h256(const ::types::H256& orig) {
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

Bytes bytes_from_h256(const ::types::H256& h256) {
    silkworm::Bytes bytes(32, '\0');
    const auto& hi{h256.hi()};
    const auto& lo{h256.lo()};
    std::memcpy(&bytes[0], bytes_from_h128(hi).data(), 16);
    std::memcpy(&bytes[16], bytes_from_h128(lo).data(), 16);
    return bytes;
}

void span_from_h256(const ::types::H256& h256, ByteSpan<32> bytes) {
    const auto& hi{h256.hi()};
    const auto& lo{h256.lo()};
    span_from_h128(hi, bytes.subspan<0, 16>());
    span_from_h128(lo, bytes.subspan<16, 16>());
}

intx::uint256 uint256_from_h256(const ::types::H256& orig) {
    uint64_t hi_hi = orig.hi().hi();
    uint64_t hi_lo = orig.hi().lo();
    uint64_t lo_hi = orig.lo().hi();
    uint64_t lo_lo = orig.lo().lo();

    return {lo_lo, lo_hi, hi_lo, hi_hi};
}

evmc::address address_from_h160(const ::types::H160& orig) {
    uint64_t hi_hi = orig.hi().hi();
    uint64_t hi_lo = orig.hi().lo();
    uint32_t lo = orig.lo();

    evmc::address dest;
    endian::store_big_u64(dest.bytes + 0, hi_hi);
    endian::store_big_u64(dest.bytes + 8, hi_lo);
    endian::store_big_u32(dest.bytes + 16, lo);

    return dest;
}

Bytes bytes_from_h128(const ::types::H128& h128) {
    Bytes bytes(16, '\0');
    endian::store_big_u64(&bytes[0], h128.hi());
    endian::store_big_u64(&bytes[8], h128.lo());
    return bytes;
}

void span_from_h128(const ::types::H128& h128, ByteSpan<16> bytes) {
    endian::store_big_u64(&bytes[0], h128.hi());
    endian::store_big_u64(&bytes[8], h128.lo());
}

std::unique_ptr<::types::H2048> h2048_from_string(std::string_view orig) {
    auto lo_lo = h512_from_string(orig);
    auto lo_hi = h512_from_string(orig.substr(64));
    auto hi_lo = h512_from_string(orig.substr(128));
    auto hi_hi = h512_from_string(orig.substr(192));

    auto hi = std::make_unique<::types::H1024>();
    auto lo = std::make_unique<::types::H1024>();

    hi->set_allocated_hi(hi_hi.release());
    hi->set_allocated_lo(hi_lo.release());
    lo->set_allocated_hi(lo_hi.release());
    lo->set_allocated_lo(lo_lo.release());

    auto dest = std::make_unique<::types::H2048>();
    dest->set_allocated_hi(hi.release());  // takes ownership
    dest->set_allocated_lo(lo.release());  // takes ownership

    return dest;
}

std::unique_ptr<::types::H2048> h2048_from_bytes(ByteView bytes) {
    auto dest = std::make_unique<::types::H2048>();
    auto hi{h1024_from_bytes({bytes.data(), 128}).release()};
    auto lo{h1024_from_bytes({bytes.data() + 128, 128}).release()};
    dest->set_allocated_hi(hi);  // takes ownership
    dest->set_allocated_lo(lo);  // takes ownership
    return dest;
}

std::unique_ptr<::types::H1024> h1024_from_bytes(ByteView bytes) {
    auto dest = std::make_unique<::types::H1024>();
    auto hi{h512_from_bytes({bytes.data(), 64}).release()};
    auto lo{h512_from_bytes({bytes.data() + 64, 64}).release()};
    dest->set_allocated_hi(hi);  // takes ownership
    dest->set_allocated_lo(lo);  // takes ownership
    return dest;
}

std::unique_ptr<::types::H512> h512_from_string(std::string_view orig) {
    Bytes bytes(64, 0);
    uint8_t* data = bytes.data();
    std::memcpy(data, orig.data(), orig.length() < 64 ? orig.length() : 64);

    auto hi_hi = std::make_unique<::types::H128>();
    auto hi_lo = std::make_unique<::types::H128>();
    auto lo_hi = std::make_unique<::types::H128>();
    auto lo_lo = std::make_unique<::types::H128>();
    hi_hi->set_hi(endian::load_big_u64(data + 0));
    hi_hi->set_lo(endian::load_big_u64(data + 8));
    hi_lo->set_hi(endian::load_big_u64(data + 16));
    hi_lo->set_lo(endian::load_big_u64(data + 24));
    lo_hi->set_hi(endian::load_big_u64(data + 32));
    lo_hi->set_lo(endian::load_big_u64(data + 40));
    lo_lo->set_hi(endian::load_big_u64(data + 48));
    lo_lo->set_lo(endian::load_big_u64(data + 56));

    auto hi = std::make_unique<::types::H256>();
    auto lo = std::make_unique<::types::H256>();
    hi->set_allocated_hi(hi_hi.release());  // takes ownership
    hi->set_allocated_lo(hi_lo.release());  // takes ownership
    lo->set_allocated_hi(lo_hi.release());  // takes ownership
    lo->set_allocated_lo(lo_lo.release());  // takes ownership

    auto dest = std::make_unique<::types::H512>();
    dest->set_allocated_hi(hi.release());  // takes ownership
    dest->set_allocated_lo(lo.release());  // takes ownership

    return dest;
}

std::unique_ptr<::types::H512> h512_from_bytes(ByteView bytes) {
    auto dest = std::make_unique<::types::H512>();
    auto hi{h256_from_bytes({bytes.data(), 32}).release()};
    auto lo{h256_from_bytes({bytes.data() + 32, 32}).release()};
    dest->set_allocated_hi(hi);  // takes ownership
    dest->set_allocated_lo(lo);  // takes ownership
    return dest;
}

void h256_from_bytes32(const evmc::bytes32& orig, ::types::H256* dest) {
    auto hi = std::make_unique<::types::H128>();
    auto lo = std::make_unique<::types::H128>();
    hi->set_hi(endian::load_big_u64(orig.bytes + 0));
    hi->set_lo(endian::load_big_u64(orig.bytes + 8));
    lo->set_hi(endian::load_big_u64(orig.bytes + 16));
    lo->set_lo(endian::load_big_u64(orig.bytes + 24));

    dest->set_allocated_hi(hi.release());  // takes ownership
    dest->set_allocated_lo(lo.release());  // takes ownership
}

std::unique_ptr<::types::H256> h256_from_bytes32(const evmc::bytes32& orig) {
    auto dest = std::make_unique<::types::H256>();
    h256_from_bytes32(orig, dest.get());
    return dest;
}

std::unique_ptr<::types::H256> h256_from_uint256(const intx::uint256& orig) {
    auto dest = std::make_unique<::types::H256>();

    auto hi = std::make_unique<::types::H128>();
    auto lo = std::make_unique<::types::H128>();

    hi->set_hi(hi_hi(orig));
    hi->set_lo(hi_lo(orig));
    lo->set_hi(lo_hi(orig));
    lo->set_lo(lo_lo(orig));

    dest->set_allocated_hi(hi.release());  // takes ownership
    dest->set_allocated_lo(lo.release());  // takes ownership

    return dest;
}

std::unique_ptr<::types::H256> h256_from_bytes(ByteView bytes) {
    auto dest = std::make_unique<::types::H256>();
    auto hi{h128_from_bytes({bytes.data(), 16}).release()};
    auto lo{h128_from_bytes({bytes.data() + 16, 16}).release()};
    dest->set_allocated_hi(hi);  // takes ownership
    dest->set_allocated_lo(lo);  // takes ownership
    return dest;
}

std::unique_ptr<::types::H160> h160_from_address(const evmc::address& orig) {
    auto hi = std::make_unique<::types::H128>();
    hi->set_hi(endian::load_big_u64(orig.bytes));
    hi->set_lo(endian::load_big_u64(orig.bytes + 8));

    auto dest = std::make_unique<::types::H160>();
    dest->set_allocated_hi(hi.release());  // takes ownership
    dest->set_lo(endian::load_big_u32(orig.bytes + 16));

    return dest;
}

std::unique_ptr<::types::H128> h128_from_bytes(ByteView bytes) {
    auto dest = std::make_unique<::types::H128>();
    dest->set_hi(endian::load_big_u64(bytes.data()));
    dest->set_lo(endian::load_big_u64(bytes.data() + 8));
    return dest;
}

}  // namespace silkworm::rpc
