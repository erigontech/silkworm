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

#include <memory>

#include <catch2/catch.hpp>

#include <silkworm/common/util.hpp>

// operator== overloading is *NOT* present in gRPC generated sources
namespace types {

TEST_CASE("H512::operator==", "[silkworm][rpc][util]") {
    CHECK(types::H512{} == types::H512{});
}

TEST_CASE("H256::operator==", "[silkworm][rpc][util]") {
    CHECK(types::H256{} == types::H256{});
}

TEST_CASE("H160::operator==", "[silkworm][rpc][util]") {
    CHECK(types::H160{} == types::H160{});
}

TEST_CASE("H128::operator==", "[silkworm][rpc][util]") {
    CHECK(types::H128{} == types::H128{});
}

}  // namespace types

namespace silkworm::rpc {

using namespace evmc::literals;

TEST_CASE("string_from_H512", "[silkworm][rpc][util]") {
    SECTION("empty H512", "[silkworm][rpc][util]") {
        CHECK_NOTHROW(string_from_H512(types::H512{}).empty());
    }

    SECTION("non-empty H512", "[silkworm][rpc][util]") {
        types::H128* hi_hi = new types::H128();
        types::H128* hi_lo = new types::H128();
        types::H128* lo_hi = new types::H128();
        types::H128* lo_lo = new types::H128();
        hi_hi->set_hi(0x7F);
        hi_hi->set_lo(0x07);
        hi_lo->set_hi(0x6F);
        hi_lo->set_lo(0x06);
        lo_hi->set_hi(0x2F);
        lo_hi->set_lo(0x02);
        lo_lo->set_hi(0x1F);
        lo_lo->set_lo(0x01);
        types::H256* hi = new types::H256{};
        types::H256* lo = new types::H256{};
        hi->set_allocated_hi(hi_hi);
        hi->set_allocated_lo(hi_lo);
        lo->set_allocated_hi(lo_hi);
        lo->set_allocated_lo(lo_lo);
        auto h512_ptr = std::make_unique<types::H512>();
        h512_ptr->set_allocated_hi(hi);
        h512_ptr->set_allocated_lo(lo);
        const std::string& s = string_from_H512(*h512_ptr);
        CHECK(s.size() == 64);
    }
}

TEST_CASE("bytes32_from_H256", "[silkworm][rpc][util]") {
    SECTION("empty H256", "[silkworm][rpc][util]") {
        CHECK_NOTHROW(bytes32_from_H256(types::H256{}) == evmc::bytes32{});
    }

    SECTION("non-empty H256", "[silkworm][rpc][util]") {
        types::H128* hi = new types::H128();
        types::H128* lo = new types::H128();
        hi->set_hi(0x7F);
        hi->set_lo(0x07);
        lo->set_hi(0x6F);
        lo->set_lo(0x06);
        auto h256_ptr = std::make_unique<types::H256>();
        h256_ptr->set_allocated_hi(hi);
        h256_ptr->set_allocated_lo(lo);
        CHECK(bytes32_from_H256(*h256_ptr) == 0x000000000000007f0000000000000007000000000000006f0000000000000006_bytes32);
    }
}

TEST_CASE("address_from_H160", "[silkworm][rpc][util]") {
    SECTION("empty H160", "[silkworm][rpc][util]") {
        CHECK_NOTHROW(address_from_H160(types::H160{}) == evmc::address{});
    }

    SECTION("non-empty H160", "[silkworm][rpc][util]") {
        types::H128* hi = new types::H128();
        hi->set_lo(0x07);
        hi->set_hi(0x7F);
        auto h160_ptr = std::make_unique<types::H160>();
        h160_ptr->set_lo(0xFF);
        h160_ptr->set_allocated_hi(hi);
        CHECK(address_from_H160(*h160_ptr) == 0x000000000000007f0000000000000007000000ff_address);
    }
}

TEST_CASE("invertibility", "[silkworm][rpc][util]") {
    SECTION("H512<->string", "[silkworm][rpc][util]") {
        types::H128* hi_hi = new types::H128();
        types::H128* hi_lo = new types::H128();
        types::H128* lo_hi = new types::H128();
        types::H128* lo_lo = new types::H128();
        hi_hi->set_hi(0x7F);
        hi_hi->set_lo(0x07);
        hi_lo->set_hi(0x6F);
        hi_lo->set_lo(0x06);
        lo_hi->set_hi(0x2F);
        lo_hi->set_lo(0x02);
        lo_lo->set_hi(0x1F);
        lo_lo->set_lo(0x01);
        types::H256* hi = new types::H256{};
        types::H256* lo = new types::H256{};
        hi->set_allocated_hi(hi_hi);
        hi->set_allocated_lo(hi_lo);
        lo->set_allocated_hi(lo_hi);
        lo->set_allocated_lo(lo_lo);
        auto h512_ptr1 = std::make_unique<types::H512>();
        h512_ptr1->set_allocated_hi(hi);
        h512_ptr1->set_allocated_lo(lo);

        const std::string& s1 = string_from_H512(*h512_ptr1);
        auto h512_ptr2 = H512_from_string(s1);

        CHECK(*h512_ptr1 == *h512_ptr2);
        const auto& s2 = string_from_H512(*h512_ptr2);
        CHECK(s1 == s2);
    }

    SECTION("H256<->bytes32", "[silkworm][rpc][util]") {
        types::H128* hi = new types::H128();
        types::H128* lo = new types::H128();
        hi->set_hi(0x7F);
        hi->set_lo(0x07);
        lo->set_hi(0x6F);
        lo->set_lo(0x06);
        auto h256_ptr1 = std::make_unique<types::H256>();
        h256_ptr1->set_allocated_hi(hi);
        h256_ptr1->set_allocated_lo(lo);

        const auto& hash1 = bytes32_from_H256(*h256_ptr1);
        auto h256_ptr2 = H256_from_bytes32(hash1);

        CHECK(*h256_ptr1 == *h256_ptr2);
        const auto& hash2 = bytes32_from_H256(*h256_ptr2);
        CHECK(hash1 == hash2);
    }

    SECTION("H160<->address", "[silkworm][rpc][util]") {
        types::H128* hi = new types::H128();
        hi->set_hi(0x7F);
        auto h160_ptr1 = std::make_unique<types::H160>();
        h160_ptr1->set_lo(0xFF);
        h160_ptr1->set_allocated_hi(hi);

        const auto& address1 = address_from_H160(*h160_ptr1);
        auto h160_ptr2 = H160_from_address(address1);

        CHECK(*h160_ptr1 == *h160_ptr2);
        const auto& address2 = address_from_H160(*h160_ptr2);
        CHECK(address1 == address2);
    }
}

}  // namespace silkworm::rpc
