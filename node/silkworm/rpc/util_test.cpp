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

#include "util.hpp"

#include <memory>

#include <catch2/catch.hpp>

#include <silkworm/common/base.hpp>

namespace silkworm::rpc {

// Factory function creating one null output stream (all characters are discarded)
std::ostream& null_stream() {
    static struct null_buf : public std::streambuf {
        int overflow(int c) override { return c; }
    } null_buf;
    static struct null_strm : public std::ostream {
        null_strm() : std::ostream(&null_buf) {}
    } null_strm;
    return null_strm;
}

using namespace evmc::literals;

TEST_CASE("print grpc::Status", "[silkworm][rpc][util]") {
    CHECK_NOTHROW(null_stream() << grpc::Status::OK);
    CHECK_NOTHROW(null_stream() << grpc::Status::CANCELLED);
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

} // namespace silkworm::rpc
