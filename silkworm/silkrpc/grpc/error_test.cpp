/*
   Copyright 2021 The Silkrpc Authors

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

#include "error.hpp"

#include <catch2/catch.hpp>

namespace silkrpc {

using Catch::Matchers::Message;

TEST_CASE("make error code with empty message", "[silkrpc][grpc][error]") {
    std::error_code error_code{make_error_code(123, "")};
    CHECK(error_code.value() == 123);
    CHECK(error_code.message() == "");
    CHECK(error_code.category().name() == std::string("grpc"));
}

TEST_CASE("make error code with non-empty message", "[silkrpc][grpc][error]") {
    std::error_code error_code{make_error_code(-123, "undefined error")};
    CHECK(error_code.value() == -123);
    CHECK(error_code.message() == "undefined error");
    CHECK(error_code.category().name() == std::string("grpc"));
}

} // namespace silkrpc

