// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <functional>
#include <optional>
#include <string>
#include <utility>

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/db/kv/api/transaction.hpp>
#include <silkworm/rpc/common/worker_pool.hpp>
#include <silkworm/rpc/core/evm_executor.hpp>
#include <silkworm/rpc/types/call.hpp>

namespace silkworm::rpc {

inline constexpr std::uint64_t kTxGas = 21'000;
inline constexpr std::uint64_t kGasCap = 50'000'000;

using BlockHeaderProvider = std::function<Task<std::optional<silkworm::BlockHeader>>(uint64_t)>;
using AccountReader = std::function<Task<std::optional<silkworm::Account>>(const evmc::address&, std::optional<TxnId> txn_id)>;

struct EstimateGasException : public std::exception {
  public:
    EstimateGasException(int64_t error_code, std::string message)
        : error_code_{error_code}, message_{std::move(message)}, data_{} {}

    EstimateGasException(int64_t error_code, std::string message, silkworm::Bytes data)
        : error_code_{error_code}, message_{std::move(message)}, data_{std::move(data)} {}

    ~EstimateGasException() noexcept override = default;

    int64_t error_code() const {
        return error_code_;
    }

    const std::string& message() const {
        return message_;
    }

    const silkworm::Bytes& data() const {
        return data_;
    }

    const char* what() const noexcept override {
        return message_.c_str();
    }

  private:
    int64_t error_code_;
    std::string message_;
    silkworm::Bytes data_;
};

class EstimateGasOracle {
  public:
    explicit EstimateGasOracle(const BlockHeaderProvider& block_header_provider,
                               const AccountReader& account_reader,
                               const silkworm::ChainConfig& config,
                               WorkerPool& workers,
                               db::kv::api::Transaction& tx,
                               const ChainStorage& chain_storage,
                               AccountsOverrides& accounts_overrides)
        : block_header_provider_(block_header_provider),
          account_reader_{account_reader},
          config_{config},
          workers_{workers},
          transaction_{tx},
          storage_{chain_storage},
          accounts_overrides_{accounts_overrides} {}
    virtual ~EstimateGasOracle() = default;

    EstimateGasOracle(const EstimateGasOracle&) = delete;
    EstimateGasOracle& operator=(const EstimateGasOracle&) = delete;

    Task<intx::uint256> estimate_gas(const Call& call, const silkworm::Block& latest_block, std::optional<TxnId> txn_id);

  protected:
    virtual ExecutionResult try_execution(EVMExecutor& executor, const silkworm::Transaction& transaction);

  private:
    void throw_exception(ExecutionResult& result);

    const BlockHeaderProvider& block_header_provider_;
    const AccountReader& account_reader_;
    const silkworm::ChainConfig& config_;
    WorkerPool& workers_;
    db::kv::api::Transaction& transaction_;
    const ChainStorage& storage_;
    AccountsOverrides& accounts_overrides_;
};

}  // namespace silkworm::rpc
