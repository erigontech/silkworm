// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/execution/evm.hpp>
#include <silkworm/core/execution/execution.hpp>
#include <silkworm/core/protocol/rule_set.hpp>
#include <silkworm/core/state/state.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/transaction.hpp>
#include <silkworm/db/chain/chain_storage.hpp>
#include <silkworm/rpc/common/worker_pool.hpp>
#include <silkworm/rpc/types/call.hpp>
#include <silkworm/rpc/types/receipt.hpp>

namespace silkworm::rpc {

enum class PreCheckErrorCode {
    kFeeCapLessThanBlockFeePerGas,
    kInsufficientFunds,
    kInternalError,
    kIntrinsicGasTooLow,
    kIsNotLondon,
    kMaxFeePerBlobGasTooLowError,
    kTipHigherThanFeeCap,
};

struct ExecutionResult {
    std::optional<evmc_status_code> status_code;
    uint64_t gas_left{0};
    std::optional<uint64_t> gas_refund;
    std::optional<uint64_t> gas_used;
    Bytes data;
    std::optional<std::string> pre_check_error{std::nullopt};
    std::optional<PreCheckErrorCode> pre_check_error_code{std::nullopt};

    bool success() const {
        return ((status_code == std::nullopt || *status_code == evmc_status_code::EVMC_SUCCESS) && pre_check_error == std::nullopt);
    }

    std::string error_message(bool full_error = true) const;
};

inline constexpr int kCacheSize = 32000;

template <typename T>
using ServiceBase = boost::asio::detail::execution_context_service_base<T>;

class AnalysisCacheService : public ServiceBase<AnalysisCacheService> {
  public:
    explicit AnalysisCacheService(boost::asio::execution_context& owner)
        : ServiceBase<AnalysisCacheService>(owner) {}

    void shutdown() override {}
    AnalysisCache* get_analysis_cache() { return &analysis_cache_; }

  private:
    AnalysisCache analysis_cache_{kCacheSize, true};
};

using db::chain::ChainStorage;
using Tracers = std::vector<std::shared_ptr<EvmTracer>>;

class EVMExecutor {
  public:
    using StateFactory = std::function<std::shared_ptr<State>(boost::asio::any_io_executor&, std::optional<TxnId>, const ChainStorage&)>;

    static Task<ExecutionResult> call(
        const silkworm::ChainConfig& config,
        const ChainStorage& storage,
        WorkerPool& workers,
        const silkworm::Block& block,
        const silkworm::Transaction& txn,
        std::optional<TxnId> txn_id,
        StateFactory state_factory,
        const Tracers& tracers = {},
        bool refund = true,
        bool gas_bailout = false,
        std::optional<AccountsOverrides> accounts_overrides = std::nullopt);
    static std::string get_error_message(int64_t error_code, const Bytes& error_data, bool full_error = true);

    EVMExecutor(const silkworm::Block& block, const silkworm::ChainConfig& config, WorkerPool& workers, std::shared_ptr<State> state)
        : config_(config),
          workers_{workers},
          state_{std::move(state)},
          rule_set_{protocol::rule_set_factory(config)},
          execution_processor_{block, *rule_set_, *state_, config, false} {
        SILKWORM_ASSERT(rule_set_);
    }
    virtual ~EVMExecutor() = default;

    static void register_service(WorkerPool& workers) { make_service<AnalysisCacheService>(workers); }

    EVMExecutor(const EVMExecutor&) = delete;
    EVMExecutor& operator=(const EVMExecutor&) = delete;

    ExecutionResult call(
        const silkworm::Transaction& txn,
        const Tracers& tracers = {},
        bool refund = true,
        bool gas_bailout = false);

    ExecutionResult call_with_receipt(
        const silkworm::Transaction& txn,
        Receipt& receipt,
        const Tracers& tracers = {},
        bool refund = true,
        bool gas_bailout = false);

    void reset();

  private:
    ExecutionResult convert_validation_result(const ValidationResult& result, const silkworm::Transaction& txn);

    const silkworm::ChainConfig& config_;
    WorkerPool& workers_;
    std::shared_ptr<State> state_;
    protocol::RuleSetPtr rule_set_;
    ExecutionProcessor execution_processor_;
};

}  // namespace silkworm::rpc
