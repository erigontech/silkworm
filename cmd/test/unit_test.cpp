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

#define CATCH_CONFIG_MAIN
#include <catch2/catch_test_macros.hpp>
#include <mutex>
#include <memory>
#include <grpcpp/grpcpp.h>
#include <silkworm/infra/grpc/server/inuseportglobalcallbacks.hpp>

std::once_flag once_flag;

auto inuseport_callback = new silkworm::rpc::InusePortGlobalCallbacks();

TEST_CASE("INITIALIZE UNIT TESTS", "") {
    std::call_once(once_flag, silkworm::rpc::set_global_callbacks, inuseport_callback);
}
