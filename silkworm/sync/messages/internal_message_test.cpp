// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "internal_message.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/db/test_util/temp_chain_data.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/sync/internals/body_sequence.hpp>

namespace silkworm {

// Switch off the null sanitizer because nullptr SentryClient is formally dereferenced in command->execute.
[[clang::no_sanitize("null")]] TEST_CASE("internal message") {
    db::test_util::TempChainDataStore context;
    // not used in the test execution
    db::DataStoreRef data_store = context->ref();
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

    command->execute(data_store, hc, bs, *sc);

    REQUIRE(!command->completed_and_read());

    auto result = command->result().get();

    REQUIRE(command->completed_and_read());
    REQUIRE(result == result_t{1, 2, 3});
}

}  // namespace silkworm
