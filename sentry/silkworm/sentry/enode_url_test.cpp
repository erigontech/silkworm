/*
Copyright 2020-2022 The Silkworm Authors

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

#include "enode_url.hpp"

#include <catch2/catch.hpp>

namespace silkworm::sentry {

TEST_CASE("EnodeUrl") {
    EnodeUrl url1("enode://aa@1.2.3.4:5");
    CHECK(url1.pub_key_hex() == "aa");
    CHECK(url1.ip().to_string() == "1.2.3.4");
    CHECK(url1.port() == 5);
    CHECK(url1.to_string() == "enode://aa@1.2.3.4:5");

    CHECK_THROWS(EnodeUrl("http://aa@1.2.3.4:5"));
    CHECK_THROWS(EnodeUrl("enode://xx@1.2.3.4:5"));
    CHECK_THROWS(EnodeUrl("enode://1.2.3.4:5"));
    CHECK_THROWS(EnodeUrl("enode://aa@90000.2.3.4:5"));
    CHECK_THROWS(EnodeUrl("enode://aa@localhost:5"));
    CHECK_THROWS(EnodeUrl("enode://aa@1.2.3.4:x"));
    CHECK_THROWS(EnodeUrl("enode://aa@1.2.3.4:90000"));
    CHECK_THROWS(EnodeUrl("enode://aa@1.2.3.4"));
}

}