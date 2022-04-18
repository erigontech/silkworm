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

namespace silkworm::rpc {

using namespace evmc::literals;

TEST_CASE("string_from_H512", "[silkworm][rpc][util]") {
    SECTION("empty H512", "[silkworm][rpc][util]") {
        CHECK_NOTHROW(string_from_H512(types::H512{}).empty());
    }

    SECTION("non-empty H512", "[silkworm][rpc][util]") {
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
        auto h512 = new types::H512{};
        h512->set_allocated_hi(hi);
        h512->set_allocated_lo(lo);
        const std::string& s = string_from_H512(*h512);
        CHECK(s.size() == 64);
    }
}

TEST_CASE("address_from_H160", "[silkworm][rpc][util]") {
    SECTION("empty H160", "[silkworm][rpc][util]") {
        CHECK_NOTHROW(address_from_H160(types::H160{}) == evmc::address{});
    }

    SECTION("non-empty H160", "[silkworm][rpc][util]") {
        auto h128_ptr = new types::H128();
        h128_ptr->set_hi(0x7F);
        auto h160_ptr = std::make_unique<types::H160>();
        h160_ptr->set_lo(0xFF);
        h160_ptr->set_allocated_hi(h128_ptr);
        CHECK(address_from_H160(*h160_ptr) == 0x000000000000007F0000000000000000000000FF_address);
    }
}

TEST_CASE("invertibility", "[silkworm][rpc][util]") {
    SECTION("H512<->string", "[silkworm][rpc][util]") {
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
        auto h512_ptr1 = std::make_unique<types::H512>();
        h512_ptr1->set_allocated_hi(hi);
        h512_ptr1->set_allocated_lo(lo);
        const std::string& s1 = string_from_H512(*h512_ptr1);
        auto h512_ptr2 = std::unique_ptr<types::H512>{new_H512_from_string(s1)};
        CHECK(h512_ptr2->lo().lo().lo() == 0x01);
        CHECK(h512_ptr2->lo().lo().hi() == 0x1F);
        CHECK(h512_ptr2->lo().hi().lo() == 0x02);
        CHECK(h512_ptr2->lo().hi().hi() == 0x2F);
        CHECK(h512_ptr2->hi().lo().lo() == 0x06);
        CHECK(h512_ptr2->hi().lo().hi() == 0x6F);
        CHECK(h512_ptr2->hi().hi().lo() == 0x07);
        CHECK(h512_ptr2->hi().hi().hi() == 0x7F);
        const auto& s2 = string_from_H512(*h512_ptr2);
        CHECK(s1 == s2);
    }

    SECTION("H160<->address", "[silkworm][rpc][util]") {
        auto h128_ptr1 = new types::H128();
        h128_ptr1->set_hi(0x7F);
        auto h160_ptr1 = std::make_unique<types::H160>();
        h160_ptr1->set_lo(0xFF);
        h160_ptr1->set_allocated_hi(h128_ptr1);
        const auto address1 = address_from_H160(*h160_ptr1);
        auto h160_ptr2 = std::unique_ptr<types::H160>{new_H160_from_address(address1)};
        auto h128_ptr2 = h160_ptr2->hi();
        CHECK(h160_ptr2->lo() == 0xFF);
        CHECK(h128_ptr1->lo() == 0x00);
        CHECK(h128_ptr1->hi() == 0x7F);
        const auto address2 = address_from_H160(*h160_ptr2);
        CHECK(address1 == address2);
    }
}

} // namespace silkworm::rpc
