// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <functional>
#include <stack>
#include <vector>

#include <evmone/baseline.hpp>
#include <evmone/execution_state.hpp>
#include <evmone/vm.hpp>
#include <gsl/pointers>
#include <intx/intx.hpp>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/lru_cache.hpp>
#include <silkworm/core/common/object_pool.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/protocol/validation.hpp>
#include <silkworm/core/state/intra_block_state.hpp>
#include <silkworm/core/types/block.hpp>

#include "silkworm/core/types/address.hpp"

namespace silkworm {

struct CallResult {
    ValidationResult validation_result{ValidationResult::kOk};
    evmc_status_code status{EVMC_SUCCESS};
    uint64_t gas_left{0};
    uint64_t gas_refund{0};
    std::optional<uint64_t> gas_used{0};
    Bytes data;
    std::string error_message;
};

class EvmTracer {
  public:
    virtual ~EvmTracer() = default;

    virtual void on_block_start(const Block& /*block*/) noexcept {}

    virtual void on_execution_start(evmc_revision /*rev*/, const evmc_message& /*msg*/, evmone::bytes_view /*code*/) noexcept {}

    virtual void on_instruction_start(uint32_t /*pc*/, const intx::uint256* /*stack_top*/, int /*stack_height*/,
                                      int64_t /*gas*/, const evmone::ExecutionState& /*state*/,
                                      const IntraBlockState& /*intra_block_state*/) noexcept {}

    virtual void on_execution_end(const evmc_result& /*result*/, const IntraBlockState& /*intra_block_state*/) noexcept {}

    virtual void on_pre_check_failed(const evmc_result& /*result*/, const evmc_message& /*msg*/) noexcept {};
    virtual void on_creation_completed(const evmc_result& /*result*/, const IntraBlockState& /*intra_block_state*/) noexcept {}

    virtual void on_precompiled_run(const evmc_result& /*result*/, const IntraBlockState& /*intra_block_state*/) noexcept {}

    virtual void on_reward_granted(const CallResult& /*result*/, const IntraBlockState& /*intra_block_state*/) noexcept {}

    virtual void on_self_destruct(const evmc::address& /*address*/, const evmc::address& /*beneficiary*/) noexcept {}

    virtual void on_block_end(const Block& /*block*/) noexcept {}
};

using EvmTracers = std::vector<std::reference_wrapper<EvmTracer>>;

using AnalysisCache = LruCache<evmc::bytes32, std::shared_ptr<evmone::baseline::CodeAnalysis>>;

using TransferFunc = void(IntraBlockState& state, const evmc::address& sender, const evmc::address& recipient,
                          const intx::uint256& amount, bool bailout);

// See consensus.Transfer in Erigon
inline void standard_transfer(IntraBlockState& state, const evmc::address& sender, const evmc::address& recipient,
                              const intx::uint256& amount, bool bailout) {
    // TODO(yperbasis) why is the bailout condition different from Erigon?
    if (!bailout || state.get_balance(sender) >= amount) {
        state.subtract_from_balance(sender, amount);
    }
    state.add_to_balance(recipient, amount);
}

class EVM {
  public:
    // Not copyable nor movable
    EVM(const EVM&) = delete;
    EVM& operator=(const EVM&) = delete;

    EVM(const Block& block, IntraBlockState& state, const ChainConfig& config) noexcept;

    ~EVM();

    /// Returns the reference to the underlying evmone's VM object.
    evmc::VM& vm() noexcept { return evm1_; }

    /// Returns the reference to the evmone's internal interface for EVM.
    evmone::VM& vm_impl() noexcept {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast)
        return *static_cast<evmone::VM*>(evm1_.get_raw_pointer());
    }

    const Block& block() const noexcept { return block_; }

    const ChainConfig& config() const noexcept { return config_; }

    IntraBlockState& state() noexcept { return state_; }
    const IntraBlockState& state() const noexcept { return state_; }

    // Precondition: txn.from must be recovered
    CallResult execute(const Transaction& txn, uint64_t gas) noexcept;

    evmc_revision revision() const noexcept;

    void add_tracer(EvmTracer& tracer) noexcept;
    void remove_tracers() noexcept;
    const EvmTracers& tracers() const noexcept { return tracers_; };

    AnalysisCache* analysis_cache{nullptr};  // provide one for better performance

    evmc_vm* exo_evm{nullptr};  // it's possible to use an exogenous EVMC VM

    evmc::address beneficiary;  // see IRuleSet::get_beneficiary

    gsl::not_null<TransferFunc*> transfer{standard_transfer};

    bool bailout{false};

    [[nodiscard]] evmc::bytes32 get_block_hash(int64_t block_num) noexcept;

  private:
    friend class EvmHost;

    evmc::Result create(const evmc_message& message) noexcept;

    evmc::Result call(const evmc_message& message) noexcept;

    evmc_result execute(const evmc_message& message, ByteView code, const evmc::bytes32* code_hash) noexcept;

    evmc_result execute_with_baseline_interpreter(evmc_revision rev, const evmc_message& message, ByteView code,
                                                  const evmc::bytes32* code_hash) noexcept;

    const Block& block_;
    IntraBlockState& state_;
    const ChainConfig& config_;
    const Transaction* txn_{nullptr};
    std::vector<evmc::bytes32> block_hashes_{};
    EvmTracers tracers_;

    // evmone is defined as static since it's stateless and doesn't have to be recreated every time EVM class is created
#ifdef __wasm__
    static evmc::VM evm1_;  // we cannot use SILKWORM_THREAD_LOCAL i.e. static in WASM (duplicate-decl-specifier)
#else
    SILKWORM_THREAD_LOCAL static evmc::VM evm1_;  // since evmone is not thread safe it should be unique per thread
#endif  // __wasm__
};

class EvmHost : public evmc::Host {
  public:
    explicit EvmHost(EVM& evm) noexcept : evm_{evm} {}

    bool account_exists(const evmc::address& address) const noexcept override;

    evmc_access_status access_account(const evmc::address& address) noexcept override;

    evmc_access_status access_storage(const evmc::address& address, const evmc::bytes32& key) noexcept override;

    evmc::bytes32 get_storage(const evmc::address& address, const evmc::bytes32& key) const noexcept override;

    evmc_storage_status set_storage(const evmc::address& address, const evmc::bytes32& key,
                                    const evmc::bytes32& value) noexcept override;

    evmc::uint256be get_balance(const evmc::address& address) const noexcept override;

    size_t get_code_size(const evmc::address& address) const noexcept override;

    evmc::bytes32 get_code_hash(const evmc::address& address) const noexcept override;

    size_t copy_code(const evmc::address& address, size_t code_offset, uint8_t* buffer_data,
                     size_t buffer_size) const noexcept override;

    bool selfdestruct(const evmc::address& address, const evmc::address& beneficiary) noexcept override;

    evmc::Result call(const evmc_message& message) noexcept override;

    evmc_tx_context get_tx_context() const noexcept override;

    evmc::bytes32 get_block_hash(int64_t block_num) const noexcept override;

    void emit_log(const evmc::address& address, const uint8_t* data, size_t data_size, const evmc::bytes32 topics[],
                  size_t num_topics) noexcept override;

    evmc::bytes32 get_transient_storage(const evmc::address& addr, const evmc::bytes32& key) const noexcept override;

    void set_transient_storage(const evmc::address& addr, const evmc::bytes32& key, const evmc::bytes32& value) noexcept override;

  private:
    EVM& evm_;
};

}  // namespace silkworm
