// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "header_retrieval.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/db/test_util/temp_chain_data.hpp>
#include <silkworm/infra/test_util/log.hpp>

namespace silkworm {

TEST_CASE("HeaderRetrieval") {
    db::test_util::TempChainDataStore context;
    context.add_genesis_data();
    context.commit_txn();

    datastore::kvdb::ROTxnManaged tx = context->chaindata().access_ro().start_ro_tx();
    db::DataModel data_model = context.data_model_factory()(tx);

    HeaderRetrieval header_retrieval{data_model};

    SECTION("recover_by_hash") {
        const auto headers{header_retrieval.recover_by_hash({}, 1, 0, false)};
    }
    SECTION("recover_by_number") {
        const auto headers{header_retrieval.recover_by_number({}, 1, 0, false)};
    }
}

}  // namespace silkworm