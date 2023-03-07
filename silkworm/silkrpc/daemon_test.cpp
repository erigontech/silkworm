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

#include "daemon.hpp"

#include <catch2/catch.hpp>

namespace silkrpc {

using Catch::Matchers::Message;

#ifndef BUILD_COVERAGE
TEST_CASE("DaemonChecklist::success_or_throw", "[silkrpc]") {
    DaemonChecklist checklist;

    SECTION("empty checklist does not throw") {
        CHECK_NOTHROW(checklist.success_or_throw());
    }

    SECTION("checklist w/ at least one incompatible throws") {
        checklist.protocol_checklist.emplace_back(ProtocolVersionResult{false, ""});
        CHECK_THROWS_AS(checklist.success_or_throw(), std::runtime_error);
    }
}
#endif // BUILD_COVERAGE

} // namespace silkrpc
