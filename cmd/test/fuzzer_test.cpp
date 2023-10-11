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

#include <silkworm/silkrpc/test/api_test_database.hpp>

using namespace silkworm::rpc::test;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
    static auto context = TestDatabaseContext();

    auto request_str = std::string(reinterpret_cast<const char*>(Data), Size);
    if (!nlohmann::json::accept(request_str)) {
        return -1;
    }

    auto request_handler = RpcApiTestBase<RequestHandler_ForTest>(context.db);
    auto request_json = nlohmann::json::parse(request_str);
    silkworm::rpc::http::Reply reply;
    request_handler.run<&RequestHandler_ForTest::handle_request>(request_str, reply);

    if (reply.status == silkworm::rpc::http::StatusType::ok) {
        return 0;
    }

    return -1;
}
