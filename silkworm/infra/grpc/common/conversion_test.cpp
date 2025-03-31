// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "conversion.hpp"

#include <array>
#include <memory>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/util.hpp>

// operator== overloading is *NOT* present in gRPC generated sources
namespace types {

TEST_CASE("H2048::operator==", "[rpc][conversion]") {
    CHECK(types::H2048{} == types::H2048{});
}

TEST_CASE("H1024::operator==", "[rpc][conversion]") {
    CHECK(types::H1024{} == types::H1024{});
}

TEST_CASE("H512::operator==", "[rpc][conversion]") {
    CHECK(types::H512{} == types::H512{});
}

TEST_CASE("H256::operator==", "[rpc][conversion]") {
    CHECK(types::H256{} == types::H256{});
}

TEST_CASE("H160::operator==", "[rpc][conversion]") {
    CHECK(types::H160{} == types::H160{});
}

TEST_CASE("H128::operator==", "[rpc][conversion]") {
    CHECK(types::H128{} == types::H128{});
}

}  // namespace types

namespace silkworm::rpc {

using namespace evmc::literals;

static Bytes kSampleH512Bytes{*from_hex(
    "000000000000007f0000000000000007000000000000006f0000000000000006"
    "000000000000002f0000000000000002000000000000001f0000000000000001")};
static std::unique_ptr<types::H512> sample_h512() {
    auto hi_hi = new types::H128();
    auto hi_lo = new types::H128();
    auto lo_hi = new types::H128();
    auto lo_lo = new types::H128();
    hi_hi->set_hi(0x7F);
    hi_hi->set_lo(0x07);
    hi_lo->set_hi(0x6F);
    hi_lo->set_lo(0x06);
    lo_hi->set_hi(0x2F);
    lo_hi->set_lo(0x02);
    lo_lo->set_hi(0x1F);
    lo_lo->set_lo(0x01);
    auto hi = new types::H256{};
    auto lo = new types::H256{};
    hi->set_allocated_hi(hi_hi);
    hi->set_allocated_lo(hi_lo);
    lo->set_allocated_hi(lo_hi);
    lo->set_allocated_lo(lo_lo);
    auto h512_ptr = std::make_unique<types::H512>();
    h512_ptr->set_allocated_hi(hi);
    h512_ptr->set_allocated_lo(lo);
    return h512_ptr;
}

TEST_CASE("string_from_h512", "[rpc][conversion]") {
    SECTION("empty H512", "[rpc][conversion]") {
        std::string zeros(64, 0);
        CHECK(string_from_h512(types::H512{}) == zeros);
    }

    SECTION("non-empty H512", "[rpc][conversion]") {
        auto h512_ptr = sample_h512();
        const std::string& s = string_from_h512(*h512_ptr);
        CHECK(s.size() == 64);
        CHECK(Bytes{reinterpret_cast<const uint8_t*>(s.data()), s.size()} == kSampleH512Bytes);
    }
}

TEST_CASE("span_from_h512", "[rpc][conversion]") {
    SECTION("empty H512", "[rpc][conversion]") {
        std::array<uint8_t, 64> zeros{};
        std::array<uint8_t, 64> uint8_array{};
        span_from_h512(types::H512{}, uint8_array);
        CHECK(uint8_array == zeros);
    }

    SECTION("non-empty H512", "[rpc][conversion]") {
        auto h512_ptr = sample_h512();
        std::array<uint8_t, 64> uint8_array{};
        span_from_h512(*h512_ptr, uint8_array);
        CHECK(Bytes{uint8_array.data(), uint8_array.size()} == kSampleH512Bytes);
    }
}

static constexpr evmc::bytes32 kSampleBytes32 = 0x000000000000007f0000000000000007000000000000006f0000000000000006_bytes32;

static std::unique_ptr<types::H256> sample_h256() {
    auto hi = new types::H128();
    auto lo = new types::H128();
    hi->set_hi(0x7F);
    hi->set_lo(0x07);
    lo->set_hi(0x6F);
    lo->set_lo(0x06);
    auto h256_ptr = std::make_unique<types::H256>();
    h256_ptr->set_allocated_hi(hi);
    h256_ptr->set_allocated_lo(lo);
    return h256_ptr;
}

TEST_CASE("bytes32_from_h256", "[rpc][conversion]") {
    SECTION("empty H256", "[rpc][conversion]") {
        CHECK_NOTHROW(bytes32_from_h256(types::H256{}) == evmc::bytes32{});
    }

    SECTION("non-empty H256", "[rpc][conversion]") {
        auto h256_ptr = sample_h256();
        CHECK(bytes32_from_h256(*h256_ptr) == kSampleBytes32);
    }
}

TEST_CASE("span_from_h256", "[rpc][conversion]") {
    SECTION("empty H256", "[rpc][conversion]") {
        evmc::bytes32 bytes32;
        span_from_h256(types::H256{}, bytes32.bytes);
        CHECK_NOTHROW(bytes32 == evmc::bytes32{});
    }

    SECTION("non-empty H256", "[rpc][conversion]") {
        auto h256_ptr = sample_h256();
        evmc::bytes32 bytes32;
        span_from_h256(*h256_ptr, bytes32.bytes);
        CHECK(bytes32 == kSampleBytes32);
    }
}

TEST_CASE("address_from_h160", "[rpc][conversion]") {
    SECTION("empty H160", "[rpc][conversion]") {
        CHECK_NOTHROW(address_from_h160(types::H160{}) == evmc::address{});
    }

    SECTION("non-empty H160", "[rpc][conversion]") {
        auto hi = new types::H128();
        hi->set_lo(0x07);
        hi->set_hi(0x7F);
        auto h160_ptr = std::make_unique<types::H160>();
        h160_ptr->set_lo(0xFF);
        h160_ptr->set_allocated_hi(hi);
        CHECK(address_from_h160(*h160_ptr) == 0x000000000000007f0000000000000007000000ff_address);
    }
}

static const Bytes kSampleBytes16 = *from_hex("0x000000000000007f0000000000000007");

static std::unique_ptr<types::H128> sample_h128() {
    auto h128_ptr = std::make_unique<::types::H128>();
    h128_ptr->set_lo(0x07);
    h128_ptr->set_hi(0x7F);
    return h128_ptr;
}

TEST_CASE("bytes_from_h128", "[rpc][conversion]") {
    SECTION("empty H128", "[rpc][conversion]") {
        Bytes zeros(16, 0);
        CHECK(bytes_from_h128(::types::H128{}) == zeros);
    }

    SECTION("non-empty H128", "[rpc][conversion]") {
        auto h128_ptr = sample_h128();
        CHECK(bytes_from_h128(*h128_ptr) == kSampleBytes16);
    }
}

TEST_CASE("span_from_h128", "[rpc][conversion]") {
    SECTION("empty H128", "[rpc][conversion]") {
        std::array<uint8_t, 16> zeros{};
        std::array<uint8_t, 16> uint8_array{};
        span_from_h128(::types::H128{}, uint8_array);
        CHECK(uint8_array == zeros);
    }

    SECTION("non-empty H128", "[rpc][conversion]") {
        auto h128_ptr = sample_h128();
        std::array<uint8_t, 16> uint8_array{};
        span_from_h128(*h128_ptr, uint8_array);
        CHECK(Bytes{uint8_array.data(), uint8_array.size()} == kSampleBytes16);
    }
}

TEST_CASE("convertibility", "[rpc][conversion]") {
    SECTION("H512<->string", "[rpc][conversion]") {
        auto h512_ptr1 = sample_h512();

        const std::string& s1 = string_from_h512(*h512_ptr1);
        auto h512_ptr2 = h512_from_string(s1);

        CHECK(*h512_ptr1 == *h512_ptr2);
        const auto& s2 = string_from_h512(*h512_ptr2);
        CHECK(s1 == s2);

        std::array<uint8_t, 64> a1{};
        span_from_h512(*h512_ptr1, a1);
        const Bytes b1{bytes_from_h512(*h512_ptr1)};
        CHECK(Bytes{a1.data(), a1.size()} == b1);
    }

    SECTION("H256<->bytes32", "[rpc][conversion]") {
        auto h256_ptr1 = sample_h256();

        const auto& hash1 = bytes32_from_h256(*h256_ptr1);
        auto h256_ptr2 = h256_from_bytes32(hash1);

        CHECK(*h256_ptr1 == *h256_ptr2);
        const auto& hash2 = bytes32_from_h256(*h256_ptr2);
        CHECK(hash1 == hash2);

        evmc::bytes32 hash3;
        span_from_h256(*h256_ptr1, hash3.bytes);
        CHECK(hash1 == hash3);
    }

    SECTION("H160<->address", "[rpc][conversion]") {
        auto hi = new types::H128();
        hi->set_hi(0x7F);
        auto h160_ptr1 = std::make_unique<types::H160>();
        h160_ptr1->set_lo(0xFF);
        h160_ptr1->set_allocated_hi(hi);

        const auto& address1 = address_from_h160(*h160_ptr1);
        auto h160_ptr2 = h160_from_address(address1);

        CHECK(*h160_ptr1 == *h160_ptr2);
        const auto& address2 = address_from_h160(*h160_ptr2);
        CHECK(address1 == address2);
    }
}

}  // namespace silkworm::rpc
