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

#include "mime_types.hpp"

#include <catch2/catch.hpp>

namespace silkrpc::http::mime_types {

using Catch::Matchers::Message;

TEST_CASE("check known extensions", "[silkrpc][http][mime_types]") {
    CHECK(extension_to_type("gif")  == "image/gif");
    CHECK(extension_to_type("htm")  == "text/html");
    CHECK(extension_to_type("html") == "text/html");
    CHECK(extension_to_type("jpg")  == "image/jpeg");
    CHECK(extension_to_type("png")  == "image/png");
}

TEST_CASE("check unknown extension", "[silkrpc][http][mime_types]") {
    CHECK(extension_to_type("foo") == "text/plain");
}

} // namespace silkrpc::http::mime_types

