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

#pragma once

#include <functional>
#include <optional>
#include <string>
#include <vector>

#include <silkworm/silkrpc/config.hpp> // NOLINT(build/include_order)

#include <boost/asio/awaitable.hpp>
#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/block.hpp>

#include <silkworm/silkrpc/core/blocks.hpp>
#include <silkworm/silkrpc/core/rawdb/accessors.hpp>
#include <silkworm/silkrpc/core/evm_executor.hpp>
#include <silkworm/silkrpc/types/call.hpp>
#include <silkworm/silkrpc/types/transaction.hpp>

namespace silkrpc::ego {

const std::uint64_t kTxGas = 21'000;
const std::uint64_t kGasCap = 25'000'000;

using BlockHeaderProvider = std::function<boost::asio::awaitable<silkworm::BlockHeader>(uint64_t)>;
using AccountReader = std::function<boost::asio::awaitable<std::optional<silkworm::Account>>(const evmc::address&, uint64_t)>;
using Executor = std::function<boost::asio::awaitable<silkrpc::ExecutionResult>(const silkworm::Transaction &)>;

struct EstimateGasException : public std::exception {
public:
    EstimateGasException(int64_t error_code, std::string const& message)
        : error_code_{error_code}, message_{message}, data_{} {}

    EstimateGasException(int64_t error_code, std::string const& message, silkworm::Bytes const& data)
        : error_code_{error_code}, message_{message}, data_{data} {}

    virtual ~EstimateGasException() noexcept {}

    int64_t error_code() const {
        return error_code_;
    }

    const std::string& message() const {
        return message_;
    }

    const silkworm::Bytes& data() const {
        return data_;
    }

    virtual const char* what() const noexcept {
       return message_.c_str();
    }

private:
    int64_t error_code_;
    std::string message_;
    silkworm::Bytes data_;
};

class EstimateGasOracle {
public:
    explicit EstimateGasOracle(const BlockHeaderProvider& block_header_provider, const AccountReader& account_reader, const Executor& executor)
        : block_header_provider_(block_header_provider), account_reader_{account_reader}, executor_(executor) {}
    virtual ~EstimateGasOracle() {}

    EstimateGasOracle(const EstimateGasOracle&) = delete;
    EstimateGasOracle& operator=(const EstimateGasOracle&) = delete;

    boost::asio::awaitable<intx::uint256> estimate_gas(const Call& call, uint64_t block_number);

private:
    boost::asio::awaitable<bool> try_execution(const silkworm::Transaction& transaction);

    const BlockHeaderProvider& block_header_provider_;
    const AccountReader& account_reader_;
    const Executor& executor_;
};

} // namespace silkrpc::ego

