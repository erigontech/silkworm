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

#include "call.hpp"

#include <catch2/catch.hpp>

namespace silkworm::rpc {

TEST_CASE("AsyncCall", "[silkworm][rpc][client][call]") {
    class FakeCall : public AsyncCall {
      public:
        explicit FakeCall(grpc::CompletionQueue* queue) : AsyncCall(queue) {}
      protected:
        bool proceed(bool /*ok*/) override { return false; }
    };

    grpc::CompletionQueue queue;

    SECTION("AsyncCall::AsyncCall") {
        FakeCall call{&queue};
        CHECK(call.peer().empty());
        CHECK(call.start_time() <= std::chrono::steady_clock::now());
        CHECK(call.status().ok());
        CHECK_NOTHROW(call.cancel());
    }
}

} // namespace silkworm::rpc
