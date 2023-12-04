/*
   Copyright 2023 The Silkworm Authors

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

#include "request.hpp"

#include <catch2/catch.hpp>

namespace silkworm::rpc::http {

TEST_CASE("check reset method", "[rpc][http][request]") {
    Request req{
        "eth_call",
        "http://localhost:8545",
        1,
        1,
        {{"Accept", "*/*"}},
        15,
        R"({"json": "2.0"})",
    };
    CHECK(req.method == "eth_call");
    CHECK(req.uri == "http://localhost:8545");
    CHECK(req.http_version_major == 1);
    CHECK(req.http_version_minor == 1);
    CHECK(req.headers == std::vector<Header>{{"Accept", "*/*"}});
    CHECK(req.content == "{\"json\": \"2.0\"}");
    CHECK(req.content_length == 15);
    req.reset();
    CHECK(req.method.empty());
    CHECK(req.uri.empty());
    CHECK(req.http_version_major == 1);
    CHECK(req.http_version_minor == 0);
    CHECK(req.headers.empty());
    CHECK(req.content.empty());
    CHECK(req.content_length == 0);
}

}  // namespace silkworm::rpc::http
