/*
   Copyright 2021 The Silkworm Authors

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

#include <catch2/catch.hpp>

#include <silkworm/common/util.hpp>

namespace silkworm::etl {

TEST_CASE("ETL Entry comparison") {
    Entry a{*from_hex("1a"), *from_hex("75")};
    Entry b{*from_hex("f7"), *from_hex("4056")};
    CHECK(a < b);
    CHECK(!(b < a));
    CHECK(!(a < a));
    CHECK(!(b < b));

    Entry c{*from_hex("ee48"), *from_hex("75")};
    Entry d{*from_hex("ee48"), *from_hex("4056")};
    CHECK(!(c < d));
    CHECK(d < c);
    CHECK(!(c < c));
    CHECK(!(d < d));
}

}  // namespace silkworm::etl
