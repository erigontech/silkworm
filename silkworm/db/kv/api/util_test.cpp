/*
   Copyright 2024 The Silkworm Authors

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

#include <catch2/catch_test_macros.hpp>

#include <silkworm/infra/test_util/log.hpp>

namespace silkworm::db::kv::api {

TEST_CASE("print Bytes", "[rpc][common][util]") {
    Bytes b{};
    CHECK_NOTHROW(test_util::null_stream() << b);
}

TEST_CASE("byte view from string", "[rpc][common][util]") {
    CHECK(byte_view_of_string("").empty());
}

TEST_CASE("bytes from string", "[rpc][common][util]") {
    CHECK(bytes_of_string("").empty());
}

TEST_CASE("print ByteView", "[rpc][common][util]") {
    Bytes b1;
    CHECK_NOTHROW(test_util::null_stream() << b1);
    Bytes b2{*from_hex("0x0608")};
    CHECK_NOTHROW(test_util::null_stream() << b2);
}

}  // namespace silkworm::db::kv::api
