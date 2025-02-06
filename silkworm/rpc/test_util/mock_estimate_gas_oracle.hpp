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
    explicit MockEstimateGasOracle(const BlockHeaderProvider& block_header_provider, const AccountReader& account_reader,
                                   const silkworm::ChainConfig& config, WorkerPool& workers, db::kv::api::Transaction& tx, const ChainStorage& storage)
        : EstimateGasOracle(block_header_provider, account_reader, config, workers, tx, storage) {}

    MOCK_METHOD((ExecutionResult), try_execution, (EVMExecutor&, const silkworm::Transaction&), (override));
};

}  // namespace silkworm::rpc
