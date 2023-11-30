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

#include "glaze.hpp"

#include <optional>
#include <string>
#include <vector>

#include <catch2/catch.hpp>
#include <evmc/evmc.hpp>
#include <intx/intx.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/node/db/access_layer.hpp>

namespace silkworm::rpc {

using Catch::Matchers::Message;
using evmc::literals::operator""_address, evmc::literals::operator""_bytes32;
using silkworm::kGiga;
using std::string_literals::operator""s;

TEST_CASE("make glaze json error", "[make_glaze_json_error]") {
    std::string json;
    make_glaze_json_error(1, 3, "generic_error", json);
    CHECK(strcmp(json.c_str(),
                 "{\"jsonrpc\":\"2.0\",\
                  \"id\":1,\
                   \"error\":{\"code\":3,\"message\":\"generic_error\"}}"));
}

TEST_CASE("make glaze json error (Revert)", "[make_glaze_json_error]") {
    std::string json;
    const char* data_hex{"c68341b58302c0"};
    silkworm::Bytes data_bytes{*silkworm::from_hex(data_hex)};
    make_glaze_json_error(1, RevertError{{3, "generic_error"}, data_bytes}, json);
    CHECK(strcmp(json.c_str(),
                 "{\"jsonrpc\":\"2.0\",\
                  \"id\":1,\
                   \"error\":{\"code\":3,\"message\":\"generic_error\",\"data\": \"0xc68341b58302c0\"}}"));
}

}  // namespace silkworm::rpc
