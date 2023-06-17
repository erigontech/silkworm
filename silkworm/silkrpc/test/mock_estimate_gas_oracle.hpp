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

#include <boost/asio/awaitable.hpp>
#include <gmock/gmock.h>

#include <silkworm/core/common/base.hpp>
#include <silkworm/silkrpc/common/util.hpp>
#include <silkworm/silkrpc/core/estimate_gas_oracle.hpp>

namespace silkworm::rpc {

class MockEstimateGasOracle : public EstimateGasOracle {
  public:
    explicit MockEstimateGasOracle(const BlockHeaderProvider& block_header_provider, const AccountReader& account_reader,
                                   const silkworm::ChainConfig& config, boost::asio::thread_pool& workers, ethdb::Transaction& tx, ethdb::TransactionDatabase& tx_database)
        : EstimateGasOracle(block_header_provider, account_reader, config, workers, tx, tx_database) {}

    MOCK_METHOD((bool), try_execution, (EVMExecutor&, const silkworm::Block&, const silkworm::Transaction&), (override));
};

}  // namespace silkworm::rpc
