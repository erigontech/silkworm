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

#include "internal_message.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/db/test_util/temp_chain_data.hpp>
#include <silkworm/sync/internals/body_sequence.hpp>

namespace silkworm {

// Switch off the null sanitizer because nullptr SentryClient is formally dereferenced in command->execute.
[[clang::no_sanitize("null")]] TEST_CASE("internal message") {
    db::test_util::TempChainData context;
    // not used in the test execution
    db::ROAccess dba(context.env());
    // not used in the test execution
    HeaderChain hc(kMainnetConfig, /* use_preverified_hashes = */ false);
    // not used in the test execution
    BodySequence bs;
    // not used in the test execution
    SentryClient* sc = nullptr;

    using result_t = std::vector<int>;

    auto command = std::make_shared<InternalMessage<result_t>>([](HeaderChain&, BodySequence&) -> result_t {
        return {1, 2, 3};
    });

    REQUIRE(!command->completed_and_read());

    command->execute(dba, hc, bs, *sc);

    REQUIRE(!command->completed_and_read());

    auto result = command->result().get();

    REQUIRE(command->completed_and_read());
    REQUIRE(result == result_t{1, 2, 3});
}

}  // namespace silkworm
