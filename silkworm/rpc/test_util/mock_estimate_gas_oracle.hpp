// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>
#include <string>

#include <silkworm/infra/concurrency/task.hpp>

#include <gmock/gmock.h>

#include <silkworm/core/common/base.hpp>
#include <silkworm/db/kv/api/transaction.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/core/estimate_gas_oracle.hpp>

namespace silkworm::rpc {

class MockEstimateGasOracle : public EstimateGasOracle {
  public:
    explicit MockEstimateGasOracle(const AccountReader& account_reader,
                                   const silkworm::ChainConfig& config, WorkerPool& workers, db::kv::api::Transaction& tx, const ChainStorage& storage, AccountsOverrides& accounts_overrides)
        : EstimateGasOracle(account_reader, config, workers, tx, storage, accounts_overrides) {}

    MOCK_METHOD((ExecutionResult), try_execution, (EVMExecutor&, const silkworm::Transaction&), (override));
};

}  // namespace silkworm::rpc
