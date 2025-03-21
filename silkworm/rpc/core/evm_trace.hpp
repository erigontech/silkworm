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

#include <deque>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <set>
#include <stack>
#include <string>
#include <variant>
#include <vector>

#include <silkworm/infra/concurrency/task.hpp>

#include <evmc/instructions.h>
#include <gsl/narrow>
#include <nlohmann/json.hpp>

#include <silkworm/core/common/block_cache.hpp>
#include <silkworm/core/execution/evm.hpp>
#include <silkworm/core/state/intra_block_state.hpp>
#include <silkworm/db/kv/api/state_cache.hpp>
#include <silkworm/db/kv/api/transaction.hpp>
#include <silkworm/rpc/common/worker_pool.hpp>
#include <silkworm/rpc/core/evm_executor.hpp>
#include <silkworm/rpc/json/stream.hpp>
#include <silkworm/rpc/types/block.hpp>
#include <silkworm/rpc/types/call.hpp>
#include <silkworm/rpc/types/transaction.hpp>

namespace silkworm::rpc::trace {

struct TraceConfig {
    bool vm_trace{false};
    bool trace{false};
    bool state_diff{false};
};

void from_json(const nlohmann::json& json, TraceConfig& tc);

struct TraceCall {
    Call call;
    TraceConfig trace_config;
};

void from_json(const nlohmann::json& json, TraceCall& tc);

struct TraceFilter {
    BlockNumOrHash from_block{0};
    BlockNumOrHash to_block{"latest"};
    std::vector<evmc::address> from_addresses;
    std::vector<evmc::address> to_addresses;
    std::optional<std::string> mode;
    std::uint32_t after{0};
    std::uint32_t count{std::numeric_limits<uint32_t>::max()};
};

void from_json(const nlohmann::json& json, TraceFilter& tf);

std::string to_string(intx::uint256 value);
std::ostream& operator<<(std::ostream& out, const TraceConfig& tc);
std::ostream& operator<<(std::ostream& out, const TraceFilter& tf);

struct TraceStorage {
    std::string key;
    std::string value;
};

struct TraceMemory {
    uint64_t offset{0};
    uint64_t len{0};
    std::string data;
};

struct TraceEx {
    int64_t used{0};
    std::optional<TraceMemory> memory;
    std::vector<std::string> stack;
    std::optional<TraceStorage> storage;
};

struct VmTrace;

struct TraceOp {
    int64_t gas_cost{0};
    std::optional<int64_t> call_gas_cap;
    std::optional<TraceEx> trace_ex;
    std::string idx;
    int32_t depth{0};
    uint8_t op_code{0};
    std::optional<std::string> op_name;
    uint32_t pc{0};
    std::shared_ptr<VmTrace> sub;
};

struct VmTrace {
    std::string code{"0x"};
    std::vector<TraceOp> ops;
};

void to_json(nlohmann::json& json, const VmTrace& vm_trace);
void to_json(nlohmann::json& json, const TraceOp& trace_op);
void to_json(nlohmann::json& json, const TraceEx& trace_ex);
void to_json(nlohmann::json& json, const TraceMemory& trace_memory);
void to_json(nlohmann::json& json, const TraceStorage& trace_storage);

void copy_address(const evmone::uint256* stack, std::string& address);
void copy_stack(std::uint8_t op_code, const evmone::uint256* stack, std::vector<std::string>& trace_stack);
void copy_memory(const evmone::Memory& memory, std::optional<TraceMemory>& trace_memory);
void copy_store(std::uint8_t op_code, const evmone::uint256* stack, std::optional<TraceStorage>& trace_storage);
void copy_memory_offset_len(std::uint8_t op_code, const evmone::uint256* stack, std::optional<TraceMemory>& trace_memory);
void push_memory_offset_len(std::uint8_t op_code, const evmone::uint256* stack, std::stack<TraceMemory>& tms);

struct FixCallGasInfo {
    int32_t depth{0};
    int64_t stipend{0};
    int16_t code_cost{0};
    TraceOp& trace_op;
    int64_t gas_cost{0};
    bool precompiled{false};
};

class VmTraceTracer : public silkworm::EvmTracer {
  public:
    explicit VmTraceTracer(VmTrace& vm_trace, std::int32_t index = -1) : vm_trace_(vm_trace), transaction_index_{index} {}

    VmTraceTracer(const VmTraceTracer&) = delete;
    VmTraceTracer& operator=(const VmTraceTracer&) = delete;

    void on_execution_start(evmc_revision rev, const evmc_message& msg, evmone::bytes_view code) noexcept override;
    void on_instruction_start(uint32_t pc, const intx::uint256* stack_top, int stack_height,
                              int64_t gas, const evmone::ExecutionState& execution_state,
                              const silkworm::IntraBlockState& intra_block_state) noexcept override;
    void on_execution_end(const evmc_result& result, const silkworm::IntraBlockState& intra_block_state) noexcept override;
    void on_pre_check_failed(const evmc_result& result, const evmc_message& msg) noexcept override;
    void on_precompiled_run(const evmc_result& result, const silkworm::IntraBlockState& intra_block_state) noexcept override;

  private:
    VmTrace& vm_trace_;
    std::int32_t transaction_index_;
    std::stack<std::string> index_prefix_;
    std::stack<std::reference_wrapper<VmTrace>> traces_stack_;
    const evmc_instruction_metrics* metrics_ = nullptr;
    std::stack<int64_t> start_gas_;
    std::stack<TraceMemory> trace_memory_stack_;
    std::optional<uint8_t> last_opcode_;
};

struct TraceAction {
    std::optional<std::string> call_type;
    evmc::address from;
    std::optional<evmc::address> to;
    int64_t gas{0};
    std::optional<silkworm::Bytes> input;
    std::optional<silkworm::Bytes> init;
    intx::uint256 value{0};
};

struct RewardAction {
    evmc::address author;
    std::string reward_type;
    intx::uint256 value{0};
};

struct SuicideAction {
    evmc::address address;
    std::string refund_address;
    intx::uint256 balance{0};
};

using Action = std::variant<TraceAction, RewardAction, SuicideAction>;

struct TraceResult {
    std::optional<evmc::address> address;
    std::optional<silkworm::Bytes> code;
    std::optional<silkworm::Bytes> output;
    int64_t gas_used{0};
};

struct Trace {
    Action action;
    std::optional<TraceResult> trace_result;
    std::int32_t sub_traces{0};
    std::vector<int32_t> trace_address;
    std::optional<std::string> error;
    std::string type;
    std::optional<evmc::bytes32> block_hash;
    std::optional<BlockNum> block_num;
    std::optional<evmc::bytes32> transaction_hash;
    std::optional<std::uint32_t> transaction_position;
    int stack_height{0};
    uint8_t op_code{0};
};

void to_json(nlohmann::json& json, const TraceAction& action);
void to_json(nlohmann::json& json, const RewardAction& action);
void to_json(nlohmann::json& json, const SuicideAction& action);
void to_json(nlohmann::json& json, const TraceResult& trace_result);
void to_json(nlohmann::json& json, const Trace& trace);

template <typename T, typename Container = std::deque<T>>
class IterableStack : public std::stack<T, Container> {
    using std::stack<T, Container>::c;

  public:
    using const_iterator = typename Container::const_iterator;

    const_iterator begin() const { return c.begin(); }
    const_iterator end() const { return std::end(c); }
};

class TraceTracer : public silkworm::EvmTracer {
  public:
    explicit TraceTracer(std::vector<Trace>& traces, silkworm::IntraBlockState& initial_ibs)
        : traces_(traces), initial_ibs_(initial_ibs) {}

    TraceTracer(const TraceTracer&) = delete;
    TraceTracer& operator=(const TraceTracer&) = delete;

    void on_execution_start(evmc_revision rev, const evmc_message& msg, evmone::bytes_view code) noexcept override;
    void on_instruction_start(uint32_t pc, const intx::uint256* stack_top, int stack_height,
                              int64_t gas, const evmone::ExecutionState& execution_state,
                              const silkworm::IntraBlockState& intra_block_state) noexcept override;
    void on_execution_end(const evmc_result& result, const silkworm::IntraBlockState& intra_block_state) noexcept override;
    void on_reward_granted(const silkworm::CallResult& result, const silkworm::IntraBlockState& intra_block_state) noexcept override;

    void on_pre_check_failed(const evmc_result& result, const evmc_message& msg) noexcept override;
    void on_creation_completed(const evmc_result& result, const silkworm::IntraBlockState& intra_block_state) noexcept override;

  private:
    bool is_precompile_{false};
    std::vector<Trace>& traces_;
    silkworm::IntraBlockState& initial_ibs_;
    std::optional<uint8_t> last_opcode_;
    int64_t initial_gas_{0};
    int32_t current_depth_{-1};
    std::set<evmc::address> created_address_;
    IterableStack<size_t> index_stack_;
    std::stack<int64_t> start_gas_;
};

struct DiffValue {
    std::optional<std::string> from;
    std::optional<std::string> to;
};

using DiffStorage = std::map<std::string, DiffValue>;

struct StateDiffEntry {
    DiffValue balance;
    DiffValue code;
    DiffValue nonce;
    DiffStorage storage;
};

using StateDiff = std::map<std::string, StateDiffEntry>;

class StateAddresses {
  public:
    explicit StateAddresses(silkworm::IntraBlockState& initial_ibs) : initial_ibs_(initial_ibs) {}

    StateAddresses(const StateAddresses&) = delete;
    StateAddresses& operator=(const StateAddresses&) = delete;

    bool exists(const evmc::address& address) const noexcept;

    intx::uint256 get_balance(const evmc::address& address) const noexcept;
    void set_balance(const evmc::address& address, const intx::uint256& value) noexcept { balances_[address] = value; }

    uint64_t get_nonce(const evmc::address& address) const noexcept;
    void set_nonce(const evmc::address& address, uint64_t nonce) noexcept { nonces_[address] = nonce; }

    silkworm::ByteView get_code(const evmc::address& address) const noexcept;
    void set_code(const evmc::address& address, silkworm::ByteView code) noexcept { codes_[address] = silkworm::Bytes{code}; }

    void remove(const evmc::address& address) noexcept;

  private:
    std::map<evmc::address, intx::uint256> balances_;
    std::map<evmc::address, uint64_t> nonces_;
    std::map<evmc::address, silkworm::Bytes> codes_;
    silkworm::IntraBlockState& initial_ibs_;
};

void to_json(nlohmann::json& json, const DiffValue& dv);
void to_json(nlohmann::json& json, const StateDiffEntry& state_diff);

class StateDiffTracer : public silkworm::EvmTracer {
  public:
    explicit StateDiffTracer(StateDiff& state_diff, StateAddresses& state_addresses) : state_diff_(state_diff), state_addresses_(state_addresses) {}

    StateDiffTracer(const StateDiffTracer&) = delete;
    StateDiffTracer& operator=(const StateDiffTracer&) = delete;

    void on_execution_start(evmc_revision rev, const evmc_message& msg, evmone::bytes_view code) noexcept override;
    void on_instruction_start(uint32_t pc, const intx::uint256* stack_top, int stack_height,
                              int64_t gas, const evmone::ExecutionState& execution_state,
                              const silkworm::IntraBlockState& intra_block_state) noexcept override;
    void on_execution_end(const evmc_result& result, const silkworm::IntraBlockState& intra_block_state) noexcept override;
    void on_reward_granted(const silkworm::CallResult& result, const silkworm::IntraBlockState& intra_block_state) noexcept override;

  private:
    bool is_precompile_{false};
    StateDiff& state_diff_;
    StateAddresses& state_addresses_;
    std::map<evmc::address, std::set<std::string>> diff_storage_;
    std::map<evmc::address, silkworm::ByteView> code_;
};

struct TraceCallTraces {
    std::string output{"0x"};
    std::optional<evmc::bytes32> transaction_hash;
    std::optional<StateDiff> state_diff;
    std::vector<Trace> trace;
    std::optional<VmTrace> vm_trace;
};

struct TraceCallResult {
    TraceCallTraces traces;
    std::optional<std::string> pre_check_error{std::nullopt};
};

struct TraceManyCallResult {
    std::vector<TraceCallTraces> traces;
    std::optional<std::string> pre_check_error{std::nullopt};
};

struct TraceDeployResult {
    std::optional<evmc::bytes32> transaction_hash;
    std::optional<evmc::address> contract_creator;
};

struct TraceEntry {
    std::string type;
    int32_t depth;
    evmc::address from;
    evmc::address to;
    std::string value;
    std::optional<std::string> input;
    std::optional<std::string> output;
};

enum OperationType : int {
    kOpTransfer = 0,
    kOpSelfDestruct = 1,
    kOpCreate = 2,
    kOpCreate2 = 3
};

struct InternalOperation {
    OperationType type;
    evmc::address from;
    evmc::address to;
    std::string value;
};

using TraceEntriesResult = std::vector<TraceEntry>;
using TraceOperationsResult = std::vector<InternalOperation>;

void to_json(nlohmann::json& json, const TraceCallTraces& result);
void to_json(nlohmann::json& json, const TraceCallResult& result);
void to_json(nlohmann::json& json, const TraceManyCallResult& result);
void to_json(nlohmann::json& json, const TraceDeployResult& result);
void to_json(nlohmann::json& json, const TraceEntry& trace_entry);
void to_json(nlohmann::json& json, const InternalOperation& trace_operation);

class IntraBlockStateTracer : public silkworm::EvmTracer {
  public:
    explicit IntraBlockStateTracer(StateAddresses& state_addresses) : state_addresses_{state_addresses} {}

    IntraBlockStateTracer(const IntraBlockStateTracer&) = delete;
    IntraBlockStateTracer& operator=(const IntraBlockStateTracer&) = delete;

    void on_reward_granted(const silkworm::CallResult& result, const silkworm::IntraBlockState& intra_block_state) noexcept override;

  private:
    StateAddresses& state_addresses_;
};

class CreateTracer : public silkworm::EvmTracer {
  public:
    explicit CreateTracer(const evmc::address& contract_address, silkworm::IntraBlockState& initial_ibs) : contract_address_(contract_address), initial_ibs_(initial_ibs) {}

    CreateTracer(const CreateTracer&) = delete;
    CreateTracer& operator=(const CreateTracer&) = delete;

    void on_execution_start(evmc_revision rev, const evmc_message& msg, evmone::bytes_view code) noexcept override;

    bool found() const { return found_; }

  private:
    bool found_{false};
    const evmc::address& contract_address_;
    const silkworm::IntraBlockState& initial_ibs_;
};

class EntryTracer : public silkworm::EvmTracer {
  public:
    explicit EntryTracer(silkworm::IntraBlockState& initial_ibs) : initial_ibs_(initial_ibs) {}

    EntryTracer(const EntryTracer&) = delete;
    EntryTracer& operator=(const EntryTracer&) = delete;

    void on_execution_start(evmc_revision rev, const evmc_message& msg, evmone::bytes_view code) noexcept override;
    void on_execution_end(const evmc_result& result, const silkworm::IntraBlockState& intra_block_state) noexcept override;
    void on_instruction_start(uint32_t pc, const intx::uint256* stack_top, int stack_height,
                              int64_t gas, const evmone::ExecutionState& execution_state,
                              const silkworm::IntraBlockState& intra_block_state) noexcept override;
    void on_self_destruct(const evmc::address& address, const evmc::address& beneficiary) noexcept override;

    TraceEntriesResult result() const { return result_; }

  private:
    const silkworm::IntraBlockState& initial_ibs_;
    TraceEntriesResult result_;
    std::stack<uint64_t> traces_stack_idx_;
    int32_t current_depth_{-1};
    std::optional<uint8_t> last_opcode_;
};

class OperationTracer : public silkworm::EvmTracer {
  public:
    explicit OperationTracer(silkworm::IntraBlockState& initial_ibs) : initial_ibs_(initial_ibs) {}

    OperationTracer(const OperationTracer&) = delete;
    OperationTracer& operator=(const OperationTracer&) = delete;

    void on_execution_start(evmc_revision rev, const evmc_message& msg, evmone::bytes_view code) noexcept override;
    void on_self_destruct(const evmc::address& address, const evmc::address& beneficiary) noexcept override;

    TraceOperationsResult result() const { return result_; }

  private:
    const silkworm::IntraBlockState& initial_ibs_;
    TraceOperationsResult result_;
};

class TouchTracer : public silkworm::EvmTracer {
  public:
    explicit TouchTracer(const evmc::address& address, silkworm::IntraBlockState& initial_ibs) : address_(address), initial_ibs_(initial_ibs) {}

    TouchTracer(const TouchTracer&) = delete;
    TouchTracer& operator=(const TouchTracer&) = delete;

    void on_execution_start(evmc_revision rev, const evmc_message& msg, evmone::bytes_view code) noexcept override;
    void on_self_destruct(const evmc::address& address, const evmc::address& beneficiary) noexcept override;

    bool found() const { return found_; }

  private:
    bool found_{false};
    const evmc::address& address_;
    const silkworm::IntraBlockState& initial_ibs_;
    TraceOperationsResult result_;
};

struct Filter {
    std::set<evmc::address> from_addresses;
    std::set<evmc::address> to_addresses;
    std::optional<std::string> mode;
    std::uint32_t after{0};
    std::uint32_t count{std::numeric_limits<uint32_t>::max()};
};

class TraceCallExecutor {
  public:
    explicit TraceCallExecutor(BlockCache& block_cache,
                               const ChainStorage& chain_storage,
                               WorkerPool& workers,
                               db::kv::api::Transaction& tx)
        : block_cache_(block_cache), chain_storage_(chain_storage), workers_(workers), tx_(tx) {}
    virtual ~TraceCallExecutor() = default;

    TraceCallExecutor(const TraceCallExecutor&) = delete;
    TraceCallExecutor& operator=(const TraceCallExecutor&) = delete;

    Task<std::vector<Trace>> trace_block(const BlockWithHash& block_with_hash, Filter& filter, json::Stream* stream = nullptr, bool is_latest_block = false);
    Task<std::vector<TraceCallResult>> trace_block_transactions(const silkworm::Block& block, const TraceConfig& config, bool is_latest_block = false);
    Task<TraceCallResult> trace_call(const silkworm::Block& block, const Call& call, const TraceConfig& config, bool is_latest_block = false);
    Task<TraceManyCallResult> trace_calls(const silkworm::Block& block, const std::vector<TraceCall>& calls, bool is_latest_block = false);
    Task<TraceDeployResult> trace_deploy_transaction(const silkworm::Block& block, const evmc::address& contract_address);
    Task<TraceCallResult> trace_transaction(const silkworm::Block& block, const rpc::Transaction& transaction, const TraceConfig& config);
    Task<std::vector<Trace>> trace_transaction(const silkworm::BlockWithHash& block, const rpc::Transaction& transaction, bool gas_bailout);
    Task<TraceEntriesResult> trace_transaction_entries(const TransactionWithBlock& transaction_with_block);
    Task<std::string> trace_transaction_error(const TransactionWithBlock& transaction_with_block);
    Task<TraceOperationsResult> trace_operations(const TransactionWithBlock& transaction_with_block);
    Task<bool> trace_touch_block(const silkworm::BlockWithHash& block_with_hash, const evmc::address& address,
                                 uint64_t block_size, const std::vector<Receipt>& receipts, TransactionsWithReceipts& results);

    Task<void> trace_filter(const TraceFilter& trace_filter, const ChainStorage& storage, json::Stream& stream);

  private:
    Task<TraceCallResult> execute(
        BlockNum block_num,
        const silkworm::Block& block,
        const rpc::Transaction& transaction,
        std::int32_t index,
        const TraceConfig& config,
        bool gas_bailout,
        bool is_latest_block);

    BlockCache& block_cache_;
    const ChainStorage& chain_storage_;
    WorkerPool& workers_;
    db::kv::api::Transaction& tx_;
};

}  // namespace silkworm::rpc::trace
