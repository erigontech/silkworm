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
#include <utility>
#include <vector>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/impl/execution_context.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/thread_pool.hpp>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/execution/evm.hpp>
#include <silkworm/core/protocol/rule_set.hpp>
#include <silkworm/core/state/state.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/transaction.hpp>
#include <silkworm/rpc/core/state_reader.hpp>
#include <silkworm/rpc/storage/chain_storage.hpp>

namespace silkworm::rpc {

enum PreCheckErrorCode {
    kFeeCapLessThanBlockFeePerGas,
    kInsufficientFunds,
    kInternalError,
    kIntrinsicGasTooLow,
    kMaxFeePerBlobGasTooLowError,
    kTipHigherThanFeeCap
};

struct ExecutionResult {
    std::optional<int64_t> error_code;
    uint64_t gas_left{0};
    Bytes data;
    std::optional<std::string> pre_check_error{std::nullopt};
    std::optional<PreCheckErrorCode> pre_check_error_code{std::nullopt};

    bool success() const {
        return ((error_code == std::nullopt || *error_code == evmc_status_code::EVMC_SUCCESS) && pre_check_error == std::nullopt);
    }

    std::string error_message(bool full_error = true) const;
};

constexpr int kCacheSize = 32000;

template <typename T>
using ServiceBase = boost::asio::detail::execution_context_service_base<T>;

class AnalysisCacheService : public ServiceBase<AnalysisCacheService> {
  public:
    explicit AnalysisCacheService(boost::asio::execution_context& owner)
        : ServiceBase<AnalysisCacheService>(owner) {}

    void shutdown() override {}
    ObjectPool<evmone::ExecutionState>* get_object_pool() { return &state_pool_; }
    AnalysisCache* get_analysis_cache() { return &analysis_cache_; }

  private:
    ObjectPool<evmone::ExecutionState> state_pool_{true};
    AnalysisCache analysis_cache_{kCacheSize, true};
};

using Tracers = std::vector<std::shared_ptr<EvmTracer>>;

class EVMExecutor {
  public:
    using StateFactory = std::function<std::shared_ptr<State>(boost::asio::any_io_executor&, BlockNum, const ChainStorage&)>;

    static Task<ExecutionResult> call(
        const silkworm::ChainConfig& config,
        const ChainStorage& storage,
        boost::asio::thread_pool& workers,
        const silkworm::Block& block,
        const silkworm::Transaction& txn,
        StateFactory state_factory,
        const Tracers& tracers = {},
        bool refund = true,
        bool gas_bailout = false);
    static std::string get_error_message(int64_t error_code, const Bytes& error_data, bool full_error = true);

    EVMExecutor(const silkworm::ChainConfig& config, boost::asio::thread_pool& workers, std::shared_ptr<State> state)
        : config_(config),
          workers_{workers},
          state_{std::move(state)},
          ibs_state_{*state_},
          rule_set_{protocol::rule_set_factory(config)} {
        SILKWORM_ASSERT(rule_set_);
        if (!has_service<AnalysisCacheService>(workers_)) {
            make_service<AnalysisCacheService>(workers_);
        }
    }
    virtual ~EVMExecutor() = default;

    EVMExecutor(const EVMExecutor&) = delete;
    EVMExecutor& operator=(const EVMExecutor&) = delete;

    ExecutionResult call(
        const silkworm::Block& block,
        const silkworm::Transaction& txn,
        const Tracers& tracers = {},
        bool refund = true,
        bool gas_bailout = false);

    void reset();

    void call_first_n(const silkworm::Block& block, uint64_t n, const Tracers& tracers = {}, bool refund = true, bool gas_bailout = false);

    const IntraBlockState& get_ibs_state() { return ibs_state_; }

  private:
    struct PreCheckResult {
        std::string pre_check_error;
        PreCheckErrorCode pre_check_error_code;
    };
    static std::optional<PreCheckResult> pre_check(const EVM& evm, const silkworm::Transaction& txn,
                                                   const intx::uint256& base_fee_per_gas, const intx::uint128& g0);
    uint64_t refund_gas(const EVM& evm, const silkworm::Transaction& txn, uint64_t gas_left, uint64_t gas_refund);

    const silkworm::ChainConfig& config_;
    boost::asio::thread_pool& workers_;
    std::shared_ptr<State> state_;
    IntraBlockState ibs_state_;
    protocol::RuleSetPtr rule_set_;
};

}  // namespace silkworm::rpc
