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

#include <string>

#include <nlohmann/json.hpp>

#include <silkworm/rpc/test_util/api_test_database.hpp>

#include "address_sanitizer_fix.hpp"

using namespace silkworm::rpc::json_rpc;
using namespace silkworm::rpc::test_util;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
    const auto request = std::string(reinterpret_cast<const char*>(Data), Size);
    if (!nlohmann::json::accept(request)) {
        return -1;
    }
    const auto request_json = nlohmann::json::parse(request);

    RpcApiE2ETest api_e2e_test;
    std::string reply;
    api_e2e_test.run<&RequestHandler_ForTest::handle_request>(request, reply);

    if (!nlohmann::json::accept(reply)) {
        return -1;
    }
    const auto reply_json = nlohmann::json::parse(reply);

    return 0;
}
