/*
   Copyright 2022 The Silkworm Authors

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

#include "evm.hpp"

#include <map>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <evmc/instructions.h>
#include <evmone/execution_state.hpp>

#include <silkworm/core/common/test_util.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/execution/call_tracer.hpp>
#include <silkworm/core/state/in_memory_state.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>

namespace silkworm {

TEST_CASE("Value transfer", "[core][execution]") {
    Block block{};
    block.header.number = 10336006;

    evmc::address from{0x0a6bb546b9208cfab9e8fa2b9b2c042b18df7030_address};
    evmc::address to{0x8b299e2b7d7f43c0ce3068263545309ff4ffb521_address};
    intx::uint256 value{10'200'000'000'000'000};

    InMemoryState db;
    IntraBlockState state{db};
    EVM evm{block, state, kMainnetConfig};

    CHECK(state.get_balance(from) == 0);
    CHECK(state.get_balance(to) == 0);

    Transaction txn{};
    txn.set_sender(from);
    txn.to = to;
    txn.value = value;

    CallResult res{evm.execute(txn, 0)};
    CHECK(res.status == EVMC_INSUFFICIENT_BALANCE);
    CHECK(res.data.empty());

    state.add_to_balance(from, kEther);

    res = evm.execute(txn, 0);
    CHECK(res.status == EVMC_SUCCESS);
    CHECK(res.data.empty());

    CHECK(state.get_balance(from) == kEther - value);
    CHECK(state.get_balance(to) == value);
    CHECK(state.touched().count(from) == 1);
    CHECK(state.touched().count(to) == 1);
}

TEST_CASE("Destruct and recreate", "[core][execution]") {
    evmc::address to{0x8b299e2b7d7f43c0ce3068263545309ff4ffb521_address};

    InMemoryState db;

    {
        IntraBlockState state{db};

        // First, create the contract and set one storage location to non-zero in a block
        state.clear_journal_and_substate();
        REQUIRE(state.get_original_storage(to, {}) == evmc::bytes32{});
        REQUIRE(state.get_current_storage(to, {}) == evmc::bytes32{});
        state.create_contract(to);
        state.set_storage(to, {}, evmc::bytes32{1});
        REQUIRE(state.get_current_storage(to, {}) == evmc::bytes32{1});
        state.finalize_transaction(EVMC_SHANGHAI);
        state.write_to_db(1);
        REQUIRE(db.state_root_hash() == 0xc2d663880f143c9bdd3c7bd2c282dc8d24e2bccf81bc779c058d18685a4a7386_bytes32);
    }

    {
        IntraBlockState state{db};

        // Then, in another block, destruct it
        state.clear_journal_and_substate();
        REQUIRE(state.get_original_storage(to, {}) == evmc::bytes32{1});
        REQUIRE(state.get_current_storage(to, {}) == evmc::bytes32{1});
        REQUIRE(state.record_suicide(to));
        state.destruct_suicides();
        REQUIRE(state.get_current_storage(to, {}) == evmc::bytes32{});
        state.finalize_transaction(EVMC_SHANGHAI);

        // Add some balance to it
        state.clear_journal_and_substate();
        state.add_to_balance(to, 1);
        state.finalize_transaction(EVMC_SHANGHAI);

        // And recreate it: the storage location previously set to non-zero must be zeroed
        state.clear_journal_and_substate();
        CHECK(state.get_original_storage(to, {}) == evmc::bytes32{});
        CHECK(state.get_current_storage(to, {}) == evmc::bytes32{});
        state.create_contract(to);
        CHECK(state.get_current_storage(to, {}) == evmc::bytes32{});
        state.finalize_transaction(EVMC_SHANGHAI);
        state.write_to_db(2);
        CHECK(db.state_root_hash() == 0x8e723de3b34ef0632b5421f0f8ad8dfa6c981e99009141b5b7130c790f0d38c6_bytes32);
    }
}

TEST_CASE("Create contract, destruct and then recreate", "[core][execution]") {
    evmc::address to{0x8b299e2b7d7f43c0ce3068263545309ff4ffb521_address};

    InMemoryState db;

    {
        IntraBlockState state{db};

        // First, create an empty contract in one block
        REQUIRE((state.get_nonce(to) == 0 && state.get_code_hash(to) == kEmptyHash));
        state.create_contract(to);
        state.set_code(to, *from_hex("30600155"));
        state.finalize_transaction(EVMC_SHANGHAI);

        state.write_to_db(1);

        const auto account{db.read_account(to)};
        CHECK((account && account->incarnation == 1));
    }

    {
        IntraBlockState state{db};

        // Then, in another block, destruct it
        state.clear_journal_and_substate();
        REQUIRE(state.record_suicide(to));
        state.destruct_suicides();
        state.finalize_transaction(EVMC_SHANGHAI);

        state.write_to_db(2);

        CHECK(!db.read_account(to));
    }

    {
        IntraBlockState state{db};

        // Finally, recreate the contract in another block
        state.create_contract(to);
        state.set_code(to, *from_hex("30600255"));
        state.finalize_transaction(EVMC_SHANGHAI);

        state.write_to_db(3);

        const auto account{db.read_account(to)};
        CHECK((account && account->incarnation == 2));
    }
}

TEST_CASE("Create empty contract and recreate non-empty in same block", "[core][execution]") {
    evmc::address to{0x8b299e2b7d7f43c0ce3068263545309ff4ffb521_address};

    InMemoryState db;
    IntraBlockState state{db};

    // First, create an empty contract in one transaction
    REQUIRE((state.get_nonce(to) == 0 && state.get_code_hash(to) == kEmptyHash));
    state.create_contract(to);
    state.finalize_transaction(EVMC_SHANGHAI);

    // Then, recreate it adding some code in another transaction
    state.clear_journal_and_substate();
    REQUIRE((state.get_nonce(to) == 0 && state.get_code_hash(to) == kEmptyHash));
    state.create_contract(to);
    state.set_code(to, *from_hex("30600055"));
    state.finalize_transaction(EVMC_SHANGHAI);

    state.write_to_db(1);

    const auto account{db.read_account(to)};
    CHECK((account && account->incarnation == 2));
}

TEST_CASE("Smart contract with storage", "[core][execution]") {
    Block block{};
    block.header.number = 1;
    evmc::address caller{0x0a6bb546b9208cfab9e8fa2b9b2c042b18df7030_address};

    // This contract initially sets its 0th storage to 0x2a
    // and its 1st storage to 0x01c9.
    // When called, it updates the 0th storage to the input provided.
    Bytes code{*from_hex("602a5f556101c960015560048060135f395ff35f355f55")};
    // https://github.com/CoinCulture/evm-tools/blob/master/analysis/guide.md#contracts
    // 0x00     PUSH1  => 2a
    // 0x02     PUSH0
    // 0x03     SSTORE         // storage[0] = 0x2a
    // 0x04     PUSH2  => 01c9
    // 0x07     PUSH1  => 01
    // 0x09     SSTORE         // storage[1] = 0x01c9
    // 0x0a     PUSH1  => 04   // deploy begin
    // 0x0c     DUP1
    // 0x0d     PUSH1  => 13
    // 0x0f     PUSH0
    // 0x10     CODECOPY
    // 0x11     PUSH0
    // 0x12     RETURN         // deploy end
    // 0x13     PUSH0          // contract code
    // 0x14     CALLDATALOAD
    // 0x15     PUSH0
    // 0x16     SSTORE         // storage[0] = input[0]

    InMemoryState db;
    IntraBlockState state{db};
    EVM evm{block, state, test::kShanghaiConfig};

    Transaction txn{};
    txn.set_sender(caller);
    txn.data = code;

    uint64_t gas{0};
    CallResult res{evm.execute(txn, gas)};
    CHECK(res.status == EVMC_OUT_OF_GAS);
    CHECK(res.data.empty());

    gas = 50'000;
    res = evm.execute(txn, gas);
    CHECK(res.status == EVMC_SUCCESS);
    CHECK(to_hex(res.data) == "5f355f55");

    evmc::address contract_address{create_address(caller, /*nonce=*/1)};
    evmc::bytes32 key0{};
    CHECK(to_hex(zeroless_view(state.get_current_storage(contract_address, key0).bytes)) == "2a");

    evmc::bytes32 new_val{to_bytes32(*from_hex("f5"))};
    txn.to = contract_address;
    txn.data = ByteView{new_val};

    res = evm.execute(txn, gas);
    CHECK(res.status == EVMC_SUCCESS);
    CHECK(res.data.empty());
    CHECK(state.get_current_storage(contract_address, key0) == new_val);
}

#if !(defined(SILKWORM_SANITIZE) && defined(__APPLE__))
TEST_CASE("Maximum call depth", "[core][execution]") {
    Block block{};
    block.header.number = 1'431'916;
    evmc::address caller{0x8e4d1ea201b908ab5e1f5a1c3f9f1b4f6c1e9cf1_address};
    evmc::address contract{0x3589d05a1ec4af9f65b0e5554e645707775ee43c_address};

    // The contract just calls itself recursively a given number of times.
    Bytes code{*from_hex("60003580600857005b6001900360005260008060208180305a6103009003f1602357fe5b")};
    /* https://github.com/CoinCulture/evm-tools
    0      PUSH1  => 00
    2      CALLDATALOAD
    3      DUP1
    4      PUSH1  => 08
    6      JUMPI
    7      STOP
    8      JUMPDEST
    9      PUSH1  => 01
    11     SWAP1
    12     SUB
    13     PUSH1  => 00
    15     MSTORE
    16     PUSH1  => 00
    18     DUP1
    19     PUSH1  => 20
    21     DUP2
    22     DUP1
    23     ADDRESS
    24     GAS
    25     PUSH2  => 0300
    28     SWAP1
    29     SUB
    30     CALL
    31     PUSH1  => 23
    33     JUMPI
    34     INVALID
    35     JUMPDEST
    */

    InMemoryState db;
    IntraBlockState state{db};
    state.set_code(contract, code);

    EVM evm{block, state, kMainnetConfig};

    AnalysisCache analysis_cache{/*max_size=*/16};
    evm.analysis_cache = &analysis_cache;

    Transaction txn{};
    txn.set_sender(caller);
    txn.to = contract;

    uint64_t gas{1'000'000};
    CallResult res{evm.execute(txn, gas)};
    CHECK(res.status == EVMC_SUCCESS);
    CHECK(res.data.empty());

    evmc::bytes32 num_of_recursions{to_bytes32(*from_hex("0400"))};
    txn.data = ByteView{num_of_recursions};
    res = evm.execute(txn, gas);
    CHECK(res.status == EVMC_SUCCESS);
    CHECK(res.data.empty());

    num_of_recursions = to_bytes32(*from_hex("0401"));
    txn.data = ByteView{num_of_recursions};
    res = evm.execute(txn, gas);
    CHECK(res.status == EVMC_INVALID_INSTRUCTION);
    CHECK(res.data.empty());
}
#endif  // SILKWORM_SANITIZE

TEST_CASE("DELEGATECALL", "[core][execution]") {
    Block block{};
    block.header.number = 1'639'560;
    evmc::address caller_address{0x8e4d1ea201b908ab5e1f5a1c3f9f1b4f6c1e9cf1_address};
    evmc::address callee_address{0x3589d05a1ec4af9f65b0e5554e645707775ee43c_address};

    // The callee writes the ADDRESS to storage.
    Bytes callee_code{*from_hex("30600055")};
    /* https://github.com/CoinCulture/evm-tools
    0      ADDRESS
    1      PUSH1  => 00
    3      SSTORE
    */

    // The caller delegate-calls the input contract.
    Bytes caller_code{*from_hex("6000808080803561eeeef4")};
    /* https://github.com/CoinCulture/evm-tools
    0      PUSH1  => 00
    2      DUP1
    3      DUP1
    4      DUP1
    5      DUP1
    6      CALLDATALOAD
    7      PUSH2  => eeee
    10     DELEGATECALL
    */

    InMemoryState db;
    IntraBlockState state{db};
    state.set_code(caller_address, caller_code);
    state.set_code(callee_address, callee_code);

    EVM evm{block, state, kMainnetConfig};

    CallTraces call_traces;
    CallTracer call_tracer{call_traces};
    evm.add_tracer(call_tracer);

    Transaction txn{};
    txn.set_sender(caller_address);
    txn.to = caller_address;
    txn.data = ByteView{to_bytes32(callee_address.bytes)};

    uint64_t gas{1'000'000};
    CallResult res{evm.execute(txn, gas)};
    CHECK(res.status == EVMC_SUCCESS);
    CHECK(res.data.empty());

    evmc::bytes32 key0{};
    CHECK(to_hex(zeroless_view(state.get_current_storage(caller_address, key0).bytes), true) == address_to_hex(caller_address));
    CHECK(call_traces.senders.size() == 1);
    CHECK(call_traces.recipients.size() == 2);
    CHECK(call_traces.senders.contains(caller_address));     // call from caller to self
    CHECK(call_traces.recipients.contains(caller_address));  // call from caller to self
    CHECK(call_traces.recipients.contains(callee_address));  // delegate call from caller to callee
}

// https://eips.ethereum.org/EIPS/eip-211#specification
TEST_CASE("CREATE should only return on failure", "[core][execution]") {
    Block block{};
    block.header.number = 4'575'910;
    evmc::address caller{0xf466859ead1932d743d622cb74fc058882e8648a_address};

    Bytes code{
        *from_hex("0x602180601360003960006000f0503d600055006211223360005260206000602060006000600461900"
                  "0f1503d60005560206000f3")};
    /* https://github.com/CoinCulture/evm-tools
    0      PUSH1  => 21
    2      DUP1
    3      PUSH1  => 13
    5      PUSH1  => 00
    7      CODECOPY
    8      PUSH1  => 00
    10     PUSH1  => 00
    12     CREATE
    13     POP
    14     RETURNDATASIZE
    15     PUSH1  => 00
    17     SSTORE
    18     STOP
    19     PUSH3  => 112233
    23     PUSH1  => 00
    25     MSTORE
    26     PUSH1  => 20
    28     PUSH1  => 00
    30     PUSH1  => 20
    32     PUSH1  => 00
    34     PUSH1  => 00
    36     PUSH1  => 04
    38     PUSH2  => 9000
    41     CALL
    42     POP
    43     RETURNDATASIZE
    44     PUSH1  => 00
    46     SSTORE
    47     PUSH1  => 20
    49     PUSH1  => 00
    51     RETURN
    */

    InMemoryState db;
    IntraBlockState state{db};
    EVM evm{block, state, kMainnetConfig};

    Transaction txn{};
    txn.set_sender(caller);
    txn.data = code;

    uint64_t gas{150'000};
    CallResult res{evm.execute(txn, gas)};
    CHECK(res.status == EVMC_SUCCESS);
    CHECK(res.data.empty());

    evmc::address contract_address{create_address(caller, /*nonce=*/0)};
    evmc::bytes32 key0{};
    CHECK(is_zero(state.get_current_storage(contract_address, key0)));
}

// https://github.com/ethereum/EIPs/issues/684
TEST_CASE("Contract overwrite", "[core][execution]") {
    Block block{};
    block.header.number = 7'753'545;

    Bytes old_code{*from_hex("6000")};
    Bytes new_code{*from_hex("6001")};

    evmc::address caller{0x92a1d964b8fc79c5694343cc943c27a94a3be131_address};

    evmc::address contract_address{create_address(caller, /*nonce=*/0)};

    InMemoryState db;
    IntraBlockState state{db};
    state.set_code(contract_address, old_code);

    EVM evm{block, state, kMainnetConfig};

    Transaction txn{};
    txn.set_sender(caller);
    txn.data = new_code;

    uint64_t gas{100'000};
    CallResult res{evm.execute(txn, gas)};

    CHECK(res.status == EVMC_INVALID_INSTRUCTION);
    CHECK(res.gas_left == 0);
    CHECK(res.data.empty());
}

TEST_CASE("EIP-3541: Reject new contracts starting with the 0xEF byte", "[core][execution]") {
    const ChainConfig& config{kMainnetConfig};

    Block block;
    block.header.number = 13'500'000;
    REQUIRE(config.revision(block.header.number, block.header.timestamp) == EVMC_LONDON);

    InMemoryState db;
    IntraBlockState state{db};
    EVM evm{block, state, config};

    Transaction txn;
    txn.set_sender(0x1000000000000000000000000000000000000000_address);
    const uint64_t gas{50'000};

    // https://eips.ethereum.org/EIPS/eip-3541#test-cases
    txn.data = *from_hex("0x60ef60005360016000f3");
    CHECK(evm.execute(txn, gas).status == EVMC_CONTRACT_VALIDATION_FAILURE);

    txn.data = *from_hex("0x60ef60005360026000f3");
    CHECK(evm.execute(txn, gas).status == EVMC_CONTRACT_VALIDATION_FAILURE);

    txn.data = *from_hex("0x60ef60005360036000f3");
    CHECK(evm.execute(txn, gas).status == EVMC_CONTRACT_VALIDATION_FAILURE);

    txn.data = *from_hex("0x60ef60005360206000f3");
    CHECK(evm.execute(txn, gas).status == EVMC_CONTRACT_VALIDATION_FAILURE);

    txn.data = *from_hex("0x60fe60005360016000f3");
    CHECK(evm.execute(txn, gas).status == EVMC_SUCCESS);
}

class TestTracer : public EvmTracer {
  public:
    explicit TestTracer(std::optional<evmc::address> contract_address = std::nullopt,
                        std::optional<evmc::bytes32> key = std::nullopt)
        : contract_address_(contract_address), key_(key), rev_{} {}

    void on_execution_start(evmc_revision rev, const evmc_message& msg, evmone::bytes_view bytecode) noexcept override {
        execution_start_called_ = true;
        rev_ = rev;
        msg_stack_.push_back(msg);
        bytecode_ = Bytes{bytecode};
    }
    void on_instruction_start(uint32_t pc, const intx::uint256* /*stack_top*/, int /*stack_height*/,
                              int64_t /*gas*/, const evmone::ExecutionState& state,
                              const IntraBlockState& intra_block_state) noexcept override {
        pc_stack_.push_back(pc);
        memory_size_stack_[pc] = state.memory.size();
        if (contract_address_) {
            storage_stack_[pc] =
                intra_block_state.get_current_storage(contract_address_.value(), key_.value_or(evmc::bytes32{}));
        }
    }
    void on_execution_end(const evmc_result& res, const IntraBlockState& intra_block_state) noexcept override {
        execution_end_called_ = true;
        const auto gas_left = static_cast<uint64_t>(res.gas_left);
        const auto gas_refund = static_cast<uint64_t>(res.gas_refund);
        result_ = {res.status_code, gas_left, gas_refund, {res.output_data, res.output_size}};
        if (contract_address_ && !pc_stack_.empty()) {
            const auto pc = pc_stack_.back();
            storage_stack_[pc] =
                intra_block_state.get_current_storage(contract_address_.value(), key_.value_or(evmc::bytes32{}));
        }
    }
    void on_creation_completed(const evmc_result& /*result*/, const IntraBlockState& /*intra_block_state*/) noexcept override {
        creation_completed_called_ = true;
    }
    void on_self_destruct(const evmc::address& /*address*/, const evmc::address& /*beneficiary*/) noexcept override {
        self_destruct_called_ = true;
    }

    void reset() {
        execution_start_called_ = false;
        execution_end_called_ = false;
        creation_completed_called_ = false;
        self_destruct_called_ = false;
        contract_address_.reset();
        key_.reset();
        rev_ = EVMC_FRONTIER;
        msg_stack_.clear();
        bytecode_.clear();
        pc_stack_.clear();
        memory_size_stack_.clear();
        storage_stack_.clear();
        result_ = {};
    }

    [[nodiscard]] bool execution_start_called() const { return execution_start_called_; }
    [[nodiscard]] bool execution_end_called() const { return execution_end_called_; }
    [[nodiscard]] bool creation_completed_called() const { return creation_completed_called_; }
    [[nodiscard]] bool self_destruct_called() const { return self_destruct_called_; }
    [[nodiscard]] const Bytes& bytecode() const { return bytecode_; }
    [[nodiscard]] const evmc_revision& rev() const { return rev_; }
    [[nodiscard]] const std::vector<evmc_message>& msg_stack() const { return msg_stack_; }
    [[nodiscard]] const std::vector<uint32_t>& pc_stack() const { return pc_stack_; }
    [[nodiscard]] const std::map<uint32_t, std::size_t>& memory_size_stack() const { return memory_size_stack_; }
    [[nodiscard]] const std::map<uint32_t, evmc::bytes32>& storage_stack() const { return storage_stack_; }
    [[nodiscard]] const CallResult& result() const { return result_; }

  private:
    bool execution_start_called_{false};
    bool execution_end_called_{false};
    bool creation_completed_called_{false};
    bool self_destruct_called_{false};
    std::optional<evmc::address> contract_address_;
    std::optional<evmc::bytes32> key_;
    evmc_revision rev_{EVMC_FRONTIER};
    std::vector<evmc_message> msg_stack_;
    Bytes bytecode_;
    std::vector<uint32_t> pc_stack_;
    std::map<uint32_t, std::size_t> memory_size_stack_;
    std::map<uint32_t, evmc::bytes32> storage_stack_;
    CallResult result_;
};

TEST_CASE("Tracing smart contract with storage", "[core][execution]") {
    Block block{};
    block.header.number = 10'336'006;
    const evmc::address caller{0x0a6bb546b9208cfab9e8fa2b9b2c042b18df7030_address};
    const evmc::address contract_address0{create_address(caller, 0)};

    // This contract initially sets its 0th storage to 0x2a and its 1st storage to 0x01c9.
    // When called, it updates the 0th storage to the input provided.
    Bytes code{*from_hex("602a6000556101c960015560068060166000396000f3600035600055")};
    // https://github.com/CoinCulture/evm-tools
    // 0      PUSH1  => 2a
    // 2      PUSH1  => 00
    // 4      SSTORE         // storage[0] = 0x2a
    // 5      PUSH2  => 01c9
    // 8      PUSH1  => 01
    // 10     SSTORE         // storage[1] = 0x01c9
    // 11     PUSH1  => 06   // deploy begin
    // 13     DUP1
    // 14     PUSH1  => 16
    // 16     PUSH1  => 00
    // 18     CODECOPY
    // 19     PUSH1  => 00
    // 21     RETURN         // deploy end
    // 22     PUSH1  => 00   // contract code
    // 24     CALLDATALOAD
    // 25     PUSH1  => 00
    // 27     SSTORE         // storage[0] = input[0]

    InMemoryState db;
    IntraBlockState state{db};
    EVM evm{block, state, kMainnetConfig};

    Transaction txn{};
    txn.set_sender(caller);
    txn.data = code;

    CHECK(evm.tracers().empty());

    // First execution: out of gas
    TestTracer tracer1;
    evm.add_tracer(tracer1);
    CallTraces call_traces1;
    CallTracer call_tracer1{call_traces1};
    evm.add_tracer(call_tracer1);
    CHECK(evm.tracers().size() == 2);

    uint64_t gas{0};
    CallResult res{evm.execute(txn, gas)};
    CHECK(res.status == EVMC_OUT_OF_GAS);
    CHECK(res.data.empty());

    CHECK((tracer1.execution_start_called() && tracer1.execution_end_called() && tracer1.creation_completed_called()));
    CHECK(tracer1.rev() == evmc_revision::EVMC_ISTANBUL);
    CHECK(tracer1.msg_stack().at(0).kind == evmc_call_kind::EVMC_CALL);
    CHECK(tracer1.msg_stack().at(0).flags == 0);
    CHECK(tracer1.msg_stack().at(0).depth == 0);
    CHECK(tracer1.msg_stack().at(0).gas == 0);
    CHECK(tracer1.bytecode() == code);
    CHECK(tracer1.pc_stack() == std::vector<uint32_t>{0});
    CHECK(tracer1.memory_size_stack() == std::map<uint32_t, std::size_t>{{0, 0}});
    CHECK(tracer1.result().status == EVMC_OUT_OF_GAS);
    CHECK(tracer1.result().gas_left == 0);
    CHECK(tracer1.result().data.empty());
    CHECK(call_traces1.senders.contains(caller));
    CHECK(call_traces1.recipients.contains(contract_address0));  // even if deployment fails

    // Second execution: success
    const evmc::address contract_address1{create_address(caller, 1)};

    TestTracer tracer2;
    evm.add_tracer(tracer2);
    CallTraces call_traces2;
    CallTracer call_tracer2{call_traces2};
    evm.add_tracer(call_tracer2);
    CHECK(evm.tracers().size() == 4);

    gas = 50'000;
    res = evm.execute(txn, gas);
    CHECK(res.status == EVMC_SUCCESS);
    CHECK(res.data == from_hex("600035600055"));

    CHECK((tracer2.execution_start_called() && tracer2.execution_end_called()));
    CHECK(tracer2.rev() == evmc_revision::EVMC_ISTANBUL);
    CHECK(tracer2.msg_stack().at(0).kind == evmc_call_kind::EVMC_CALL);
    CHECK(tracer2.msg_stack().at(0).flags == 0);
    CHECK(tracer2.msg_stack().at(0).depth == 0);
    CHECK(tracer2.msg_stack().at(0).gas == 50'000);
    CHECK(tracer2.bytecode() == code);
    CHECK(tracer2.pc_stack() == std::vector<uint32_t>{0, 2, 4, 5, 8, 10, 11, 13, 14, 16, 18, 19, 21});
    CHECK(tracer2.memory_size_stack() == std::map<uint32_t, std::size_t>{{0, 0},
                                                                         {2, 0},
                                                                         {4, 0},
                                                                         {5, 0},
                                                                         {8, 0},
                                                                         {10, 0},
                                                                         {11, 0},
                                                                         {13, 0},
                                                                         {14, 0},
                                                                         {16, 0},
                                                                         {18, 0},
                                                                         {19, 32},
                                                                         {21, 32}});
    CHECK(tracer2.result().status == EVMC_SUCCESS);
    CHECK(tracer2.result().gas_left == 9964);
    CHECK(tracer2.result().data == res.data);
    CHECK(call_traces2.senders.contains(caller));
    CHECK(call_traces2.recipients.contains(contract_address1));

    // Third execution: success
    evmc::bytes32 key0{};

    TestTracer tracer3{contract_address1, key0};
    evm.add_tracer(tracer3);
    CallTraces call_traces3;
    CallTracer call_tracer3{call_traces3};
    evm.add_tracer(call_tracer3);
    CHECK(evm.tracers().size() == 6);

    CHECK(to_hex(zeroless_view(state.get_current_storage(contract_address1, key0).bytes)) == "2a");
    evmc::bytes32 new_val{to_bytes32(*from_hex("f5"))};
    txn.to = contract_address1;
    txn.data = ByteView{new_val};
    gas = 50'000;
    res = evm.execute(txn, gas);
    CHECK(res.status == EVMC_SUCCESS);
    CHECK(res.data.empty());
    CHECK(state.get_current_storage(contract_address1, key0) == new_val);

    CHECK((tracer3.execution_start_called() && tracer3.execution_end_called()));
    CHECK(tracer3.rev() == evmc_revision::EVMC_ISTANBUL);
    CHECK(tracer3.msg_stack().at(0).kind == evmc_call_kind::EVMC_CALL);
    CHECK(tracer3.msg_stack().at(0).flags == 0);
    CHECK(tracer3.msg_stack().at(0).depth == 0);
    CHECK(tracer3.msg_stack().at(0).gas == 50'000);
    CHECK(tracer3.storage_stack() == std::map<uint32_t, evmc::bytes32>{
                                         {0, to_bytes32(*from_hex("2a"))},
                                         {2, to_bytes32(*from_hex("2a"))},
                                         {3, to_bytes32(*from_hex("2a"))},
                                         {5, to_bytes32(*from_hex("f5"))},
                                     });
    CHECK(tracer3.pc_stack() == std::vector<uint32_t>{0, 2, 3, 5});
    CHECK(tracer3.memory_size_stack() == std::map<uint32_t, std::size_t>{{0, 0}, {2, 0}, {3, 0}, {5, 0}});
    CHECK(tracer3.result().status == EVMC_SUCCESS);
    CHECK(tracer3.result().gas_left == 49191);
    CHECK(tracer3.result().data.empty());
    CHECK(call_traces3.senders.contains(caller));
    CHECK(call_traces3.recipients.contains(contract_address1));
}

TEST_CASE("Tracing smart contract creation with CREATE", "[core][execution]") {
    Block block{};
    block.header.number = 10'336'006;
    const evmc::address caller{0x0a6bb546b9208cfab9e8fa2b9b2c042b18df7030_address};

    Bytes code{*from_hex(
        "6080604052348015600f57600080fd5b50604051601a90603b565b6040518091"
        "03906000f0801580156035573d6000803e3d6000fd5b50506047565b605c8061"
        "009483390190565b603f806100556000396000f3fe6080604052600080fdfea2"
        "646970667358221220a6baacd5f97c2b771bee61b48c72a104dab25ffee7f1d6"
        "a26fcd81322047223364736f6c634300081300336080604052348015600f5760"
        "0080fd5b50603f80601d6000396000f3fe6080604052600080fdfea264697066"
        "7358221220f6587bd1dd592bb64698cf04f378d03a5f9e55c27c86df8890b628"
        "7d8694a43164736f6c63430008130033")};
    // pragma solidity 0.8.19;
    //
    // contract Factory {
    //     constructor() {
    //         new Item();
    //     }
    // }
    // contract Item {
    //     constructor() {}
    // }

    InMemoryState db;
    IntraBlockState state{db};
    EVM evm{block, state, kMainnetConfig};

    Transaction txn{};
    txn.set_sender(caller);
    txn.data = code;

    TestTracer tracer;
    evm.add_tracer(tracer);
    CallTraces call_traces;
    CallTracer call_tracer{call_traces};
    evm.add_tracer(call_tracer);
    CHECK(evm.tracers().size() == 2);

    const auto factory0_address{create_address(caller, state.get_nonce(caller))};
    const auto item0_address{create_address(factory0_address, 1)};

    uint64_t gas1 = {100'000};  // largely abundant (required 57'470)
    CallResult res1{evm.execute(txn, gas1)};

    CHECK(res1.status == EVMC_SUCCESS);
    CHECK(tracer.msg_stack().size() == 2);
    if (tracer.msg_stack().size() == 2) {
        CHECK(tracer.msg_stack().at(0).depth == 0);
        CHECK(tracer.msg_stack().at(0).kind == evmc_call_kind::EVMC_CALL);
        CHECK(tracer.msg_stack().at(0).recipient == factory0_address);
        CHECK(evmc::is_zero(tracer.msg_stack().at(0).code_address));
        CHECK(tracer.msg_stack().at(1).depth == 1);
        CHECK(tracer.msg_stack().at(1).kind == evmc_call_kind::EVMC_CREATE);
        CHECK(tracer.msg_stack().at(1).recipient == item0_address);
    }
    CHECK(evmc::is_zero(tracer.msg_stack().at(1).code_address));
    CHECK(call_traces.senders.size() == 2);
    CHECK(call_traces.senders.contains(caller));
    CHECK(call_traces.senders.contains(factory0_address));
    CHECK(call_traces.recipients.size() == 2);
    CHECK(call_traces.recipients.contains(factory0_address));
    CHECK(call_traces.recipients.contains(item0_address));

    tracer.reset();
    call_traces.senders.clear();
    call_traces.recipients.clear();

    // Trigger an early failure in evmone::baseline::check_requirements for CREATE opcode
    const auto factory1_address{create_address(caller, state.get_nonce(caller))};
    const auto item1_address{create_address(factory1_address, 1)};

    uint64_t gas2 = {138};  // causes out-of-gas at instruction 34 opcode CREATE in check_requirements
    CallResult res2 = evm.execute(txn, gas2);
    CHECK(res2.status == EVMC_OUT_OF_GAS);
    CHECK(tracer.msg_stack().size() == 1);
    if (tracer.msg_stack().size() == 1) {
        CHECK(tracer.msg_stack().at(0).depth == 0);
        CHECK(tracer.msg_stack().at(0).kind == evmc_call_kind::EVMC_CALL);
        CHECK(tracer.msg_stack().at(0).recipient == factory1_address);
        CHECK(evmc::is_zero(tracer.msg_stack().at(0).code_address));
    }
    CHECK(call_traces.senders.size() == 1);
    CHECK(call_traces.senders.contains(caller));
    CHECK(!call_traces.senders.contains(factory1_address));
    CHECK(call_traces.recipients.size() == 1);
    CHECK(call_traces.recipients.contains(factory1_address));
    CHECK(!call_traces.recipients.contains(item1_address));
}

TEST_CASE("Tracing smart contract creation with CREATE2", "[core][execution]") {
    Block block{};
    block.header.number = 10'336'006;
    const evmc::address caller{0x0a6bb546b9208cfab9e8fa2b9b2c042b18df7030_address};

    Bytes code{*from_hex(
        "6080604052348015600f57600080fd5b506000801b604051601e906043565b81"
        "90604051809103906000f5905080158015603d573d6000803e3d6000fd5b5050"
        "604f565b605c8061009c83390190565b603f8061005d6000396000f3fe608060"
        "4052600080fdfea2646970667358221220ffaf2d6fdd061c3273248388b99d0e"
        "48f13466b078ba552718eb14d618127f5f64736f6c6343000813003360806040"
        "52348015600f57600080fd5b50603f80601d6000396000f3fe60806040526000"
        "80fdfea2646970667358221220ea2cccbd9b69291ff50e3244e6b74392bb58de"
        "7268abedc75e862628e939d32e64736f6c63430008130033")};
    // pragma solidity 0.8.19;
    //
    // contract Factory {
    //     constructor() {
    //         new TestContract{salt: 0}();
    //     }
    // }
    // contract TestContract {
    //     constructor() {}
    // }

    InMemoryState db;
    IntraBlockState state{db};
    EVM evm{block, state, kMainnetConfig};

    Transaction txn{};
    txn.set_sender(caller);
    txn.data = code;

    TestTracer tracer;
    evm.add_tracer(tracer);
    CallTraces call_traces;
    CallTracer call_tracer{call_traces};
    evm.add_tracer(call_tracer);
    CHECK(evm.tracers().size() == 2);

    uint64_t gas = {100'000};
    CallResult res{evm.execute(txn, gas)};

    CHECK(tracer.msg_stack().at(0).depth == 0);
    CHECK(tracer.msg_stack().at(0).kind == evmc_call_kind::EVMC_CALL);
    CHECK(tracer.msg_stack().at(0).recipient == 0xb7698071d0a593014f241f9d7fbbc49bcd62e014_address);
    CHECK(evmc::is_zero(tracer.msg_stack().at(0).code_address));
    CHECK(tracer.msg_stack().at(1).depth == 1);
    CHECK(tracer.msg_stack().at(1).kind == evmc_call_kind::EVMC_CREATE2);
    CHECK(tracer.msg_stack().at(1).recipient == 0xe3e8f1881ba12f7d2494c010422982a8bf6045f7_address);
    CHECK(evmc::is_zero(tracer.msg_stack().at(1).code_address));
    CHECK(call_traces.senders.contains(caller));
    CHECK(call_traces.recipients.contains(0xb7698071d0a593014f241f9d7fbbc49bcd62e014_address));
    CHECK(call_traces.recipients.contains(0xe3e8f1881ba12f7d2494c010422982a8bf6045f7_address));
}

TEST_CASE("Tracing smart contract w/o code", "[core][execution]") {
    Block block{};
    block.header.number = 10'336'006;

    InMemoryState db;
    IntraBlockState state{db};
    EVM evm{block, state, kMainnetConfig};
    CHECK(evm.tracers().empty());

    TestTracer tracer1;
    evm.add_tracer(tracer1);
    CHECK(evm.tracers().size() == 1);

    // Deploy contract without code
    evmc::address caller{0x0a6bb546b9208cfab9e8fa2b9b2c042b18df7030_address};
    Bytes code{};

    Transaction txn{};
    txn.set_sender(caller);
    txn.data = code;
    uint64_t gas{50'000};

    CallResult res{evm.execute(txn, gas)};
    CHECK(res.status == EVMC_SUCCESS);
    CHECK(res.data.empty());

    CHECK(tracer1.execution_start_called());
    CHECK(tracer1.execution_end_called());
    CHECK(tracer1.rev() == evmc_revision::EVMC_ISTANBUL);
    CHECK(tracer1.bytecode() == code);
    CHECK(tracer1.pc_stack().empty());
    CHECK(tracer1.memory_size_stack().empty());
    CHECK(tracer1.result().status == EVMC_SUCCESS);
    CHECK(tracer1.result().gas_left == gas);
    CHECK(tracer1.result().data.empty());

    // Send message to empty contract
    evmc::address contract_address{create_address(caller, 1)};
    evmc::bytes32 key0{};

    TestTracer tracer2{contract_address, key0};
    evm.add_tracer(tracer2);
    CHECK(evm.tracers().size() == 2);

    txn.to = contract_address;
    txn.data = ByteView{to_bytes32(*from_hex("f5"))};
    res = evm.execute(txn, gas);
    CHECK(res.status == EVMC_SUCCESS);
    CHECK(res.data.empty());

    CHECK(tracer2.execution_start_called());
    CHECK(tracer2.execution_end_called());
    CHECK(tracer2.rev() == evmc_revision::EVMC_ISTANBUL);
    CHECK(tracer2.bytecode() == code);
    CHECK(tracer2.pc_stack().empty());
    CHECK(tracer2.memory_size_stack().empty());
    CHECK(tracer2.result().status == EVMC_SUCCESS);
    CHECK(tracer2.result().gas_left == gas);
    CHECK(tracer2.result().data.empty());
}

TEST_CASE("Tracing precompiled contract failure", "[core][execution]") {
    Block block{};
    block.header.number = 10'336'006;

    InMemoryState db;
    IntraBlockState state{db};
    EVM evm{block, state, kMainnetConfig};
    CHECK(evm.tracers().empty());

    TestTracer tracer1;
    evm.add_tracer(tracer1);
    CHECK(evm.tracers().size() == 1);

    // Execute transaction Deploy contract without code
    evmc::address caller{0x0a6bb546b9208cfab9e8fa2b9b2c042b18df7030_address};

    evmc::address blake2f_precompile{0x0000000000000000000000000000000000000009_address};

    Transaction txn{};
    txn.set_sender(caller);
    txn.to = blake2f_precompile;
    uint64_t gas{50'000};

    CallResult res{evm.execute(txn, gas)};
    CHECK(res.status == EVMC_PRECOMPILE_FAILURE);
}

TEST_CASE("Smart contract creation w/ insufficient balance", "[core][execution]") {
    Block block{};
    block.header.number = 1;
    const evmc::address caller{0x0a6bb546b9208cfab9e8fa2b9b2c042b18df7030_address};

    Bytes code{*from_hex("602a5f556101c960015560048060135f395ff35f355f55")};

    InMemoryState db;
    IntraBlockState state{db};
    EVM evm{block, state, test::kShanghaiConfig};

    CallTraces call_traces;
    CallTracer call_tracer{call_traces};
    evm.add_tracer(call_tracer);

    Transaction txn{};
    txn.set_sender(caller);
    txn.data = code;
    txn.value = intx::uint256{1};

    uint64_t gas = 50'000;
    CallResult res = evm.execute(txn, gas);
    CHECK(res.status == EVMC_INSUFFICIENT_BALANCE);
    CHECK(call_traces.senders.empty());     // No call tracer notification (compatibility w/ Erigon)
    CHECK(call_traces.recipients.empty());  // No call tracer notification (compatibility w/ Erigon)
}

TEST_CASE("Smart contract creation w/ insufficient gas", "[core][execution]") {
    Block block{};
    block.header.number = 1;
    const evmc::address caller{0x0a6bb546b9208cfab9e8fa2b9b2c042b18df7030_address};
    const evmc::address contract_address{create_address(caller, 0)};

    Bytes code{*from_hex("602a5f556101c960015560048060135f395ff35f355f55")};

    InMemoryState db;
    IntraBlockState state{db};
    EVM evm{block, state, test::kShanghaiConfig};

    CallTraces call_traces;
    CallTracer call_tracer{call_traces};
    evm.add_tracer(call_tracer);

    Transaction txn{};
    txn.set_sender(caller);
    txn.data = code;

    uint64_t gas = 10'000;
    CallResult res = evm.execute(txn, gas);
    CHECK(res.status == EVMC_OUT_OF_GAS);
    CHECK(call_traces.senders.size() == 1);
    CHECK(call_traces.senders.contains(caller));
    CHECK(call_traces.recipients.size() == 1);
    CHECK(call_traces.recipients.contains(contract_address));
}

TEST_CASE("Tracing destruction of smart contract", "[core][execution]") {
    // Deployed code compiled using solc 0.8.19+commit.4fc1097e
    const Bytes deployed_code{*from_hex(
        "6080604052348015600f57600080fd5b506004361060285760003560e01c8063"
        "41c0e1b514602d575b600080fd5b60336035565b005b600073ffffffffffffff"
        "ffffffffffffffffffffffffff16fffea2646970667358221220c08c48851b75"
        "79ee6720e88f475624478fb5b0287b58e91a51315b243356fb9264736f6c6343"
        "0008130033")};
    // pragma solidity 0.8.19;
    //
    // contract TestContract {
    //     constructor() {}
    //
    //     function kill() public {
    //         selfdestruct(payable(address(0)));
    //     }
    // }

    // Bytecode contains SHR opcode so requires EIP-145, hence at least Constantinople HF
    const auto chain_config{kMainnetConfig};
    REQUIRE(chain_config.constantinople_block);

    Block block{};
    block.header.number = *chain_config.constantinople_block;
    const evmc::address caller{0x0a6bb546b9208cfab9e8fa2b9b2c042b18df7030_address};
    const evmc::address contract_address{create_address(caller, 0)};

    InMemoryState db;
    IntraBlockState state{db};
    state.set_code(contract_address, deployed_code);

    EVM evm{block, state, chain_config};
    REQUIRE(evm.revision() >= EVMC_CONSTANTINOPLE);
    TestTracer test_tracer;
    evm.add_tracer(test_tracer);
    CallTraces call_traces;
    CallTracer call_tracer{call_traces};
    evm.add_tracer(call_tracer);
    CHECK(evm.tracers().size() == 2);

    Transaction txn{};
    txn.set_sender(caller);
    txn.to = contract_address;
    txn.data = ByteView{*from_hex("41c0e1b5")};  // methodID for kill

    uint64_t gas = {100'000};
    CallResult res = evm.execute(txn, gas);
    CHECK(res.status == EVMC_SUCCESS);
    CHECK(test_tracer.self_destruct_called());
    CHECK(call_traces.senders.size() == 2);
    CHECK(call_traces.recipients.size() == 2);
    CHECK(call_traces.senders.contains(caller));               // external tx
    CHECK(call_traces.recipients.contains(contract_address));  // external tx
    CHECK(call_traces.senders.contains(contract_address));     // self-destruct
    CHECK(call_traces.recipients.contains(evmc::address{}));   // self-destruct
}

// First occurrence at mainnet block 116'525
TEST_CASE("State changes for creation+destruction of smart contract", "[core][execution]") {
    // Bytecode compiled using solc 0.8.19+commit.4fc1097e
    const Bytes code{*from_hex(
        "6080604052348015600f57600080fd5b5060858061001e6000396000f3fe"
        "6080604052348015600f57600080fd5b506004361060285760003560e01c8063"
        "41c0e1b514602d575b600080fd5b60336035565b005b600073ffffffffffffff"
        "ffffffffffffffffffffffffff16fffea2646970667358221220c08c48851b75"
        "79ee6720e88f475624478fb5b0287b58e91a51315b243356fb9264736f6c6343"
        "0008130033")};
    // pragma solidity 0.8.19;
    //
    // contract TestContract {
    //     constructor() {}
    //
    //     function kill() public {
    //         selfdestruct(payable(address(0)));
    //     }
    // }

    // Bytecode contains SHR opcode so requires EIP-145, hence at least Constantinople HF
    const auto chain_config{kMainnetConfig};
    REQUIRE(chain_config.constantinople_block);

    Block block{};
    block.header.number = *chain_config.constantinople_block;
    constexpr auto zero_address = 0x0000000000000000000000000000000000000000_address;
    constexpr auto caller{0x0a6bb546b9208cfab9e8fa2b9b2c042b18df7030_address};
    const auto contract_address{create_address(caller, 0)};

    InMemoryState db;
    IntraBlockState state{db};

    EVM evm{block, state, chain_config};
    REQUIRE(evm.revision() >= EVMC_CONSTANTINOPLE);
    TestTracer test_tracer;
    evm.add_tracer(test_tracer);

    // 1st tx creates the code at contract_address, thus changing such account state
    Transaction txn1{};
    txn1.set_sender(caller);
    txn1.data = code;

    uint64_t gas = {100'000};
    CallResult res1{evm.execute(txn1, gas)};
    CHECK(res1.status == EVMC_SUCCESS);
    CHECK(test_tracer.creation_completed_called());

    state.finalize_transaction(EVMC_CONSTANTINOPLE);
    state.clear_journal_and_substate();

    // 2nd tx destroys the contract triggering self-destruct, thus changing such account back to empty state
    Transaction txn2{};
    txn2.set_sender(caller);
    txn2.to = contract_address;
    txn2.data = ByteView{*from_hex("41c0e1b5")};  // methodID for kill

    CallResult res2 = evm.execute(txn2, gas);
    CHECK(res2.status == EVMC_SUCCESS);
    CHECK(test_tracer.self_destruct_called());

    state.finalize_transaction(EVMC_CONSTANTINOPLE);
    state.write_to_db(block.header.number);

    CHECK(!db.accounts().contains(contract_address));

    const auto account_changes_per_block{db.account_changes()};
    CHECK(account_changes_per_block.contains(block.header.number));
    if (account_changes_per_block.contains(block.header.number)) {
        const auto& account_changes{account_changes_per_block.at(block.header.number)};
        CHECK(account_changes.contains(caller));             // transaction caller pays for execution
        CHECK(!account_changes.contains(zero_address));      // destruction beneficiary receives zero balance (hence unchanged)
        CHECK(!account_changes.contains(contract_address));  // contract address hasn't changed after all
    }
    CHECK(state.number_of_self_destructs() == 1);
}

// First occurrence at mainnet block 1'639'553
TEST_CASE("Missing sender in call traces for DELEGATECALL", "[core][execution]") {
    constexpr auto zero_address = 0x0000000000000000000000000000000000000000_address;
    evmc::address external_account{0xf466859ead1932d743d622cb74fc058882e8648a_address};
    const auto caller_address{create_address(external_account, 0)};
    const auto callee_address{create_address(external_account, 1)};

    // The callee writes the ADDRESS to storage.
    const Bytes callee_code{*from_hex("30600055")};
    /* https://github.com/CoinCulture/evm-tools
    0      ADDRESS
    1      PUSH1  => 00
    3      SSTORE
    */

    // The caller delegate-calls the input contract.
    const Bytes caller_code{*from_hex("6000808080803561eeeef4")};
    /* https://github.com/CoinCulture/evm-tools
    0      PUSH1  => 00
    2      DUP1
    3      DUP1
    4      DUP1
    5      DUP1
    6      CALLDATALOAD
    7      PUSH2  => eeee
    10     DELEGATECALL
    */

    Block block{};
    block.header.number = 1'639'553;
    InMemoryState db;
    IntraBlockState state{db};

    EVM evm{block, state, kMainnetConfig};

    CallTraces call_traces;
    CallTracer call_tracer{call_traces};
    evm.add_tracer(call_tracer);

    // 1st tx creates the code at caller_address
    Transaction txn1{};
    txn1.set_sender(external_account);
    txn1.data = caller_code;

    uint64_t gas = {1'000'000};
    CallResult res1{evm.execute(txn1, gas)};

    CHECK(res1.status == EVMC_SUCCESS);

    state.set_code(caller_address, caller_code);
    state.finalize_transaction(EVMC_CONSTANTINOPLE);
    state.clear_journal_and_substate();

    // 2nd tx creates the code at callee_address
    Transaction txn2{};
    txn2.set_sender(external_account);
    txn2.data = callee_code;

    CallResult res2 = evm.execute(txn2, gas);

    CHECK(res2.status == EVMC_SUCCESS);

    state.set_code(callee_address, callee_code);
    state.finalize_transaction(EVMC_CONSTANTINOPLE);
    state.clear_journal_and_substate();

    // 3rd tx calls the code at caller_address which in turn delegate-calls the code at callee address
    Transaction txn3{};
    txn3.set_sender(external_account);
    txn3.to = caller_address;
    txn3.data = ByteView{to_bytes32(callee_address.bytes)};

    CallResult res3{evm.execute(txn3, gas)};
    CHECK(res3.status == EVMC_SUCCESS);
    CHECK(res3.data.empty());

    state.finalize_transaction(EVMC_CONSTANTINOPLE);
    state.write_to_db(block.header.number);

    evmc::bytes32 key0{};
    CHECK(to_hex(zeroless_view(db.storage().at(caller_address).at(1).at(key0).bytes), true) == address_to_hex(caller_address));
    CHECK(call_traces.senders.size() == 2);
    CHECK(call_traces.senders.contains(external_account));  // all txs originates from external_account
    CHECK(call_traces.senders.contains(caller_address));    // 3rd tx triggers one delegate call from caller_address
    CHECK(call_traces.recipients.size() == 3);
    CHECK(call_traces.recipients.contains(zero_address));    // 1st+2nd txs go to zero_address (contract creation)
    CHECK(call_traces.recipients.contains(caller_address));  // 3rd tx goes to caller_address
    CHECK(call_traces.recipients.contains(callee_address));  // 3rd tx triggers one delegate call to callee_address
}

// First occurrence at mainnet block 1'305'821
TEST_CASE("Missing call traces for CREATE/CREATE2 when completed w/o executing", "[core][execution]") {
    const evmc::address external_account{0x0a6bb546b9208cfab9e8fa2b9b2c042b18df7030_address};

    // Bytecode compiled using solc 0.8.19+commit.4fc1097e
    const Bytes item_code{*from_hex(
        "6080604052348015600f57600080fd5b50603f80601d6000396000f3fe60806040"
        "52600080fdfea2646970667358221220a3544cc91a06a14e2a9610d3b786201808"
        "2accb02f8555e847bc238a80ec0ec664736f6c63430008130033")};
    // pragma solidity 0.8.19;
    //
    // contract Item {
    //     constructor() {}
    // }

    const Bytes factory_and_test_contract_code{*from_hex(
        "608060405234801561001057600080fd5b5061014d806100206000396000f3fe60"
        "8060405234801561001057600080fd5b50600436106100365760003560e01c8063"
        "efc81a8c1461003b578063f5eacece14610045575b600080fd5b61004361004f56"
        "5b005b61004d61007b565b005b60405161005b906100af565b6040518091039060"
        "00f080158015610077573d6000803e3d6000fd5b5050565b6000801b6040516100"
        "8b906100af565b8190604051809103906000f59050801580156100ab573d600080"
        "3e3d6000fd5b5050565b605c806100bc8339019056fe6080604052348015600f57"
        "600080fd5b50603f80601d6000396000f3fe6080604052600080fdfea264697066"
        "7358221220a3544cc91a06a14e2a9610d3b7862018082accb02f8555e847bc238a"
        "80ec0ec664736f6c63430008130033a26469706673582212207dbb3b4abbeee927"
        "e9bf764d2f83d595ce57ab4f1a5f5db3b84aaa22d5cdf4a264736f6c6343000813"
        "0033")};
    // pragma solidity 0.8.19;
    //
    // contract Factory {
    //     constructor() {}
    //
    //     function create() public {
    //         new Item();
    //     }
    //
    //     function create2() public {
    //         new Item{salt: 0}();
    //     }
    // }
    //
    // contract Item {
    //     constructor() {}
    // }

    // Bytecode contains PUSH0 opcode so requires EIP-3855, hence at least Shanghai HF
    const auto chain_config{kMainnetConfig};
    REQUIRE(chain_config.shanghai_time);

    Block block{};
    block.header.number = 18'700'000;

    InMemoryState db;
    IntraBlockState state{db};
    EVM evm{block, state, kMainnetConfig};

    // 1st tx deploys the factory at factory_address
    const auto factory_address{create_address(external_account, 0)};

    Transaction txn1{};
    txn1.set_sender(external_account);
    txn1.data = factory_and_test_contract_code;

    TestTracer tracer;
    evm.add_tracer(tracer);
    CallTraces call_traces;
    CallTracer call_tracer{call_traces};
    evm.add_tracer(call_tracer);
    CHECK(evm.tracers().size() == 2);

    uint64_t gas1 = {1'000'000};  // largely abundant
    CallResult res1{evm.execute(txn1, gas1)};

    CHECK(res1.status == EVMC_SUCCESS);
    CHECK(call_traces.senders.size() == 1);
    CHECK(call_traces.senders.contains(external_account));  // 1st tx originates from external_account
    CHECK(call_traces.recipients.size() == 1);
    CHECK(call_traces.recipients.contains(factory_address));  // 1st tx goes to factory_address

    call_traces.senders.clear();
    call_traces.recipients.clear();

    // 2nd tx asks the factory to deploy an item using CREATE at item1_address
    const auto item1_address{create_address(factory_address, 1)};

    Transaction txn2{};
    txn2.set_sender(external_account);
    txn2.to = factory_address;
    txn2.data = ByteView{*from_hex("efc81a8c")};  // methodID for create

    uint64_t gas2 = {1'000'000};  // largely abundant
    CallResult res2{evm.execute(txn2, gas2)};

    CHECK(res2.status == EVMC_SUCCESS);
    CHECK(call_traces.senders.size() == 2);
    CHECK(call_traces.senders.contains(external_account));  // 2nd tx originates from external_account
    CHECK(call_traces.senders.contains(factory_address));
    CHECK(call_traces.recipients.size() == 2);
    CHECK(call_traces.recipients.contains(factory_address));  // 2nd tx goes to factory_address
    CHECK(call_traces.recipients.contains(item1_address));

    call_traces.senders.clear();
    call_traces.recipients.clear();

    // 3rd tx asks the factory to deploy an item using CREATE2 at item2_address
    ethash::hash256 item_code_hash{keccak256(item_code)};
    const auto item2_address{create2_address(factory_address, evmc::bytes32{0}, item_code_hash.bytes)};

    Transaction txn3{};
    txn3.set_sender(external_account);
    txn3.to = factory_address;
    txn3.data = ByteView{*from_hex("f5eacece")};  // methodID for create2

    uint64_t gas3 = {1'000'000};  // largely abundant
    CallResult res3{evm.execute(txn3, gas3)};

    CHECK(res3.status == EVMC_SUCCESS);
    CHECK(call_traces.senders.size() == 2);
    CHECK(call_traces.senders.contains(external_account));  // 3rd tx originates from external_account
    CHECK(call_traces.senders.contains(factory_address));   // item creation originates from factory_address
    CHECK(call_traces.recipients.size() == 2);
    CHECK(call_traces.recipients.contains(factory_address));  // 3rd tx goes to factory_address
    CHECK(call_traces.recipients.contains(item2_address));    // item gets deployed at item2_address

    call_traces.senders.clear();
    call_traces.recipients.clear();

    // 4th execution is like 2nd but triggers early failure in check_requirements due to insufficient gas
    const auto item1bis_address{create_address(factory_address, 3)};

    uint64_t gas4 = {10'000};
    CallResult res4{evm.execute(txn2, gas4)};

    CHECK(res4.status == EVMC_OUT_OF_GAS);
    CHECK(call_traces.senders.size() == 1);
    CHECK(call_traces.senders.contains(external_account));  // 2nd tx originates from external_account
    CHECK(!call_traces.senders.contains(factory_address));  // factory_address not traced because creation failed
    CHECK(call_traces.recipients.size() == 1);
    CHECK(call_traces.recipients.contains(factory_address));    // 2nd tx goes to factory_address
    CHECK(!call_traces.recipients.contains(item1bis_address));  // item1bis_address not traced because creation failed

    call_traces.senders.clear();
    call_traces.recipients.clear();

    // 5th execution is like 3rd but triggers early failure in check_requirements due to insufficient gas
    uint64_t gas5 = {10'000};
    CallResult res5{evm.execute(txn3, gas5)};

    CHECK(res5.status == EVMC_OUT_OF_GAS);
    CHECK(call_traces.senders.size() == 1);
    CHECK(call_traces.senders.contains(external_account));  // 3rd tx originates from external_account
    CHECK(!call_traces.senders.contains(factory_address));  // factory_address not traced because creation failed
    CHECK(call_traces.recipients.size() == 1);
    CHECK(call_traces.recipients.contains(factory_address));  // 3rd tx goes to factory_address
    CHECK(!call_traces.recipients.contains(item2_address));   // item2_address not traced because creation failed
}

//! CallGasTracer collects gas cost for CALL opcodes
class CallGasCostTracer : public EvmTracer {
  public:
    explicit CallGasCostTracer() = default;

    CallGasCostTracer(const CallGasCostTracer&) = delete;
    CallGasCostTracer& operator=(const CallGasCostTracer&) = delete;

    //    void on_instruction_start(uint32_t pc, const intx::uint256* stack_top, int stack_height, int64_t gas,
    //                              const evmone::ExecutionState& state, const IntraBlockState& intra_block_state) noexcept override;
    void on_instruction_start(unsigned int pc, const intx::uint256*, int, long gas,
                              const evmone::ExecutionState& execution_state,
                              const IntraBlockState&) noexcept override {
        const auto opcode = execution_state.original_code[pc];

        if (temporary_gas_) {
            auto cost = temporary_gas_.value() - gas;  // ops gas cost is evaluated as gas_left difference
            call_gas_cost_.push_back(cost);
            temporary_gas_.reset();
        }
        if (opcode == 0xf1) {  // CALL
            temporary_gas_ = gas;
        }
    }

    const std::vector<long>& call_gas_cost() const {
        return call_gas_cost_;
    }

  private:
    std::optional<long> temporary_gas_;
    std::vector<long> call_gas_cost_;
};

TEST_CASE("Get gas cost for CALL", "[core][execution]") {
    Block block{};
    block.header.number = 1'029'553;  // real block on GOERLI chain see https://goerli.etherscan.io/block/1029553

    evmc::address sender_address{0x8882042B8E93C85312f623F058eF252c8025a7Ae_address};

    evmc::address callee_address{0x37803fC1b1FA2075B6D79f3e4CDF2873B9237281_address};
    // The callee code.
    Bytes callee_code{*from_hex("600035601c52740100000000000000000000000000000000000000006020526f7fffffffffffffffffffffffffffffff6040527fffffffffffffffffffffffffffffffff8000000000000000000000000000000060605274012a05f1fffffffffffffffffffffffffdabf41c006080527ffffffffffffffffffffffffed5fa0e000000000000000000000000000000000060a0526000156101a3575b6101605261014052601860086020820661018001602082840111156100bf57600080fd5b6020806101a082610140600060046015f1505081815280905090509050805160200180610240828460006004600a8704601201f16100fc57600080fd5b50506102405160206001820306601f82010390506102a0610240516008818352015b826102a051111561012e5761014a565b60006102a05161026001535b815160010180835281141561011e575b5050506020610220526040610240510160206001820306601f8201039050610200525b60006102005111151561017f5761019b565b602061020051036102200151602061020051036102005261016d565b610160515650005b600015610387575b6101605261014052600061018052610140516101a0526101c060006008818352015b61018051600860008112156101ea578060000360020a82046101f1565b8060020a82025b905090506101805260ff6101a051166101e052610180516101e0516101805101101561021c57600080fd5b6101e0516101805101610180526101a0517ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff86000811215610265578060000360020a820461026c565b8060020a82025b905090506101a0525b81516001018083528114156101cd575b5050601860086020820661020001602082840111156102a357600080fd5b60208061022082610180600060046015f15050818152809050905090508051602001806102c0828460006004600a8704601201f16102e057600080fd5b50506102c05160206001820306601f82010390506103206102c0516008818352015b826103205111156103125761032e565b6000610320516102e001535b8151600101808352811415610302575b50505060206102a05260406102c0510160206001820306601f8201039050610280525b6000610280511115156103635761037f565b602061028051036102a001516020610280510361028052610351565b610160515650005b63863a311b60005114156106185734156103a057600080fd5b6000610140526101405161016052600354610180526101a060006020818352015b60016001610180511614156104425760006101a051602081106103e357600080fd5b600260c052602060c02001546020826102400101526020810190506101605160208261024001015260208101905080610240526102409050602060c0825160208401600060025af161043457600080fd5b60c0519050610160526104b0565b6000610160516020826101c00101526020810190506101a0516020811061046857600080fd5b600160c052602060c02001546020826101c0010152602081019050806101c0526101c09050602060c0825160208401600060025af16104a657600080fd5b60c0519050610160525b61018060026104be57600080fd5b60028151048152505b81516001018083528114156103c1575b505060006101605160208261044001015260208101905061014051610160516101805163806732896102c0526003546102e0526102e051600658016101ab565b506103405260006103a0525b6103405160206001820306601f82010390506103a0511015156105455761055e565b6103a05161036001526103a0516020016103a052610523565b61018052610160526101405261034060088060208461044001018260208501600060046012f150508051820191505060006018602082066103c001602082840111156105a957600080fd5b6020806103e082610140600060046015f150508181528090509050905060188060208461044001018260208501600060046014f150508051820191505080610440526104409050602060c0825160208401600060025af161060957600080fd5b60c051905060005260206000f3005b63621fd130600051141561072a57341561063157600080fd5b6380673289610140526003546101605261016051600658016101ab565b506101c0526000610220525b6101c05160206001820306601f82010390506102205110151561067c57610695565b610220516101e00152610220516020016102205261065a565b6101c0805160200180610280828460006004600a8704601201f16106b857600080fd5b50506102805160206001820306601f82010390506102e0610280516008818352015b826102e05111156106ea57610706565b60006102e0516102a001535b81516001018083528114156106da575b5050506020610260526040610280510160206001820306601f8201039050610260f3005b63c47e300d600051141561128257606060046101403760506004356004016101a037603060043560040135111561076057600080fd5b604060243560040161022037602060243560040135111561078057600080fd5b60806044356004016102803760606044356004013511156107a057600080fd5b63ffffffff600354106107b257600080fd5b633b9aca0061034052610340516107c857600080fd5b610340513404610320526000546103205110156107e457600080fd5b60306101a051146107f457600080fd5b6020610220511461080457600080fd5b6060610280511461081457600080fd5b6101a0516101c0516101e05161020051610220516102405161026051610280516102a0516102c0516102e05161030051610320516103405161036051610380516103a05163806732896103c052610320516103e0526103e051600658016101ab565b506104405260006104a0525b6104405160206001820306601f82010390506104a0511015156108a4576108bd565b6104a05161046001526104a0516020016104a052610882565b6103a05261038052610360526103405261032052610300526102e0526102c0526102a05261028052610260526102405261022052610200526101e0526101c0526101a052610440805160200180610360828460006004600a8704601201f161092457600080fd5b50506101a0516101c0516101e05161020051610220516102405161026051610280516102a0516102c0516102e05161030051610320516103405161036051610380516103a0516103c0516103e05161040051610420516104405161046051610480516104a05163806732896104c0526003546104e0526104e051600658016101ab565b506105405260006105a0525b6105405160206001820306601f82010390506105a0511015156109d5576109ee565b6105a05161056001526105a0516020016105a0526109b3565b6104a05261048052610460526104405261042052610400526103e0526103c0526103a05261038052610360526103405261032052610300526102e0526102c0526102a05261028052610260526102405261022052610200526101e0526101c0526101a0526105408051602001806105c0828460006004600a8704601201f1610a7557600080fd5b505060a06106405261064051610680526101a08051602001806106405161068001828460006004600a8704601201f1610aad57600080fd5b505061064051610680015160206001820306601f8201039050610640516106800161062081516040818352015b8361062051101515610aeb57610b08565b6000610620516020850101535b8151600101808352811415610ada575b50505050602061064051610680015160206001820306601f820103905061064051010161064052610640516106a0526102208051602001806106405161068001828460006004600a8704601201f1610b5f57600080fd5b505061064051610680015160206001820306601f8201039050610640516106800161062081516020818352015b8361062051101515610b9d57610bba565b6000610620516020850101535b8151600101808352811415610b8c575b50505050602061064051610680015160206001820306601f820103905061064051010161064052610640516106c0526103608051602001806106405161068001828460006004600a8704601201f1610c1157600080fd5b505061064051610680015160206001820306601f8201039050610640516106800161062081516020818352015b8361062051101515610c4f57610c6c565b6000610620516020850101535b8151600101808352811415610c3e575b50505050602061064051610680015160206001820306601f820103905061064051010161064052610640516106e0526102808051602001806106405161068001828460006004600a8704601201f1610cc357600080fd5b505061064051610680015160206001820306601f8201039050610640516106800161062081516060818352015b8361062051101515610d0157610d1e565b6000610620516020850101535b8151600101808352811415610cf0575b50505050602061064051610680015160206001820306601f82010390506106405101016106405261064051610700526105c08051602001806106405161068001828460006004600a8704601201f1610d7557600080fd5b505061064051610680015160206001820306601f8201039050610640516106800161062081516020818352015b8361062051101515610db357610dd0565b6000610620516020850101535b8151600101808352811415610da2575b50505050602061064051610680015160206001820306601f8201039050610640510101610640527f649bbc62d0e31342afea4e5cd82d4049e7e1ee912fc0889aa790803be39038c561064051610680a160006107205260006101a06030806020846107e001018260208501600060046016f150508051820191505060006010602082066107600160208284011115610e6757600080fd5b60208061078082610720600060046015f15050818152809050905090506010806020846107e001018260208501600060046013f1505080518201915050806107e0526107e09050602060c0825160208401600060025af1610ec757600080fd5b60c0519050610740526000600060406020820661088001610280518284011115610ef057600080fd5b6060806108a0826020602088068803016102800160006004601bf1505081815280905090509050602060c0825160208401600060025af1610f3057600080fd5b60c0519050602082610a800101526020810190506000604060206020820661094001610280518284011115610f6457600080fd5b606080610960826020602088068803016102800160006004601bf1505081815280905090509050602080602084610a0001018260208501600060046015f150508051820191505061072051602082610a0001015260208101905080610a0052610a009050602060c0825160208401600060025af1610fe157600080fd5b60c0519050602082610a8001015260208101905080610a8052610a809050602060c0825160208401600060025af161101857600080fd5b60c0519050610860526000600061074051602082610b20010152602081019050610220602080602084610b2001018260208501600060046015f150508051820191505080610b2052610b209050602060c0825160208401600060025af161107e57600080fd5b60c0519050602082610ca00101526020810190506000610360600880602084610c2001018260208501600060046012f15050805182019150506000601860208206610ba001602082840111156110d357600080fd5b602080610bc082610720600060046015f1505081815280905090509050601880602084610c2001018260208501600060046014f150508051820191505061086051602082610c2001015260208101905080610c2052610c209050602060c0825160208401600060025af161114657600080fd5b60c0519050602082610ca001015260208101905080610ca052610ca09050602060c0825160208401600060025af161117d57600080fd5b60c0519050610b0052600380546001825401101561119a57600080fd5b6001815401815550600354610d2052610d4060006020818352015b60016001610d20511614156111ea57610b0051610d4051602081106111d957600080fd5b600260c052602060c020015561127e565b6000610d4051602081106111fd57600080fd5b600260c052602060c0200154602082610d60010152602081019050610b0051602082610d6001015260208101905080610d6052610d609050602060c0825160208401600060025af161124e57600080fd5b60c0519050610b0052610d20600261126557600080fd5b60028151048152505b81516001018083528114156111b5575b5050005b639890220b60005114156112b657341561129b57600080fd5b600060006000600030316004546000f16112b457600080fd5b005b631ea30fef60005114156112dc5734156112cf57600080fd5b60005460005260206000f3005b63eb8545ee60005114156113025734156112f557600080fd5b60035460005260206000f3005b638ba35cdf600051141561132857341561131b57600080fd5b60045460005260206000f3005b60006000fd")};

    InMemoryState db;
    IntraBlockState state{db};

    state.set_balance(0x0000000000000000000000000000000000000000_address, intx::from_string<intx::uint256>("0x01"));
    state.set_balance(sender_address, intx::from_string<intx::uint256>("0x70155dca4fd46a6b49"));
    state.set_nonce(sender_address, 0xb02);
    state.set_code(callee_address, callee_code);
    state.set_balance(callee_address, intx::from_string<intx::uint256>("0x1ab6f94d08a0800000"));
    state.set_nonce(callee_address, 0x1);

    EVM evm{block, state, kGoerliConfig};

    CallGasCostTracer tracer;
    evm.add_tracer(tracer);

    Transaction txn{};  // txn #0 in block 1'029'553, see https://goerli.etherscan.io/tx/0x81b9951cde95115515c6049382e8227dc9a96972793df7da814ab22cc62dd091
    txn.set_sender(sender_address);
    txn.to = callee_address;
    txn.data = ByteView{*from_hex("9890220b")};

    uint64_t gas{3'978'728};
    CallResult res{evm.execute(txn, gas)};
    CHECK(res.status == EVMC_SUCCESS);
    const auto& call_gas_cost = tracer.call_gas_cost();
    CHECK(call_gas_cost.size() == 1);
<<<<<<< HEAD
    CHECK(call_gas_cost[0] == 3);
//    CHECK(res.data.empty());
//
//    evmc::bytes32 key0{};
//    CHECK(to_hex(zeroless_view(state.get_current_storage(caller_address, key0).bytes), true) == address_to_hex(caller_address));
//    CHECK(call_traces.senders.size() == 1);
//    CHECK(call_traces.recipients.size() == 2);
//    CHECK(call_traces.senders.contains(caller_address));     // call from caller to self
//    CHECK(call_traces.recipients.contains(caller_address));  // call from caller to self
//    CHECK(call_traces.recipients.contains(callee_address));  // delegate call from caller to callee
=======
    CHECK(call_gas_cost[0] == 7400);  // CALL gas cost resulting in silk rpcdaemon
    //    CHECK(call_gas_cost[0] == 9700); // CALL gas cost expected according to erigon rpcdaemon
>>>>>>> e0a79b78 (refinement)
}

//! CallGasTracer collects gas cost for CALL opcodes
class CallGasCostTracer : public EvmTracer {
public:
    explicit CallGasCostTracer() = default;

    CallGasCostTracer(const CallGasCostTracer&) = delete;
    CallGasCostTracer& operator=(const CallGasCostTracer&) = delete;

    //    void on_instruction_start(uint32_t pc, const intx::uint256* stack_top, int stack_height, int64_t gas,
    //                              const evmone::ExecutionState& state, const IntraBlockState& intra_block_state) noexcept override;
    void on_instruction_start(unsigned int pc, const intx::uint256* stack_top, int stack_height, long gas,
                              const evmone::ExecutionState& execution_state,
                              const IntraBlockState&) noexcept override {
        const auto opcode = execution_state.original_code[pc];

        if (temporary_gas_) {
            auto cost = temporary_gas_.value() - gas;  // ops gas cost is evaluated as gas_left difference
            call_gas_cost_.push_back(cost);
            temporary_gas_.reset();
        }
        if (opcode == OP_CALL || opcode == OP_STATICCALL || opcode == OP_CALLCODE || opcode == OP_DELEGATECALL || opcode == OP_CREATE || opcode == OP_CREATE2) {
            if (opcode == OP_CALL && stack_height >= 7 && stack_top[-2] != 0) {
                temporary_gas_ = gas + 2300;  // for CALLs with value, include stipend
            } else {
                temporary_gas_ = gas;
            }
        }
    }

    const std::vector<long>& call_gas_cost() const {
        return call_gas_cost_;
    }

private:
    std::optional<long> temporary_gas_;
    std::vector<long> call_gas_cost_;
};

TEST_CASE("Get gas cost for CALL #1", "[core][execution]") {
    Block block{};
    block.header.number = 1'029'553;  // real block on GOERLI chain see https://goerli.etherscan.io/block/1029553

    evmc::address sender_address{0x8882042B8E93C85312f623F058eF252c8025a7Ae_address};

    evmc::address callee_address{0x37803fC1b1FA2075B6D79f3e4CDF2873B9237281_address};
    // The callee code.
    Bytes callee_code{*from_hex("600035601c52740100000000000000000000000000000000000000006020526f7fffffffffffffffffffffffffffffff6040527fffffffffffffffffffffffffffffffff8000000000000000000000000000000060605274012a05f1fffffffffffffffffffffffffdabf41c006080527ffffffffffffffffffffffffed5fa0e000000000000000000000000000000000060a0526000156101a3575b6101605261014052601860086020820661018001602082840111156100bf57600080fd5b6020806101a082610140600060046015f1505081815280905090509050805160200180610240828460006004600a8704601201f16100fc57600080fd5b50506102405160206001820306601f82010390506102a0610240516008818352015b826102a051111561012e5761014a565b60006102a05161026001535b815160010180835281141561011e575b5050506020610220526040610240510160206001820306601f8201039050610200525b60006102005111151561017f5761019b565b602061020051036102200151602061020051036102005261016d565b610160515650005b600015610387575b6101605261014052600061018052610140516101a0526101c060006008818352015b61018051600860008112156101ea578060000360020a82046101f1565b8060020a82025b905090506101805260ff6101a051166101e052610180516101e0516101805101101561021c57600080fd5b6101e0516101805101610180526101a0517ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff86000811215610265578060000360020a820461026c565b8060020a82025b905090506101a0525b81516001018083528114156101cd575b5050601860086020820661020001602082840111156102a357600080fd5b60208061022082610180600060046015f15050818152809050905090508051602001806102c0828460006004600a8704601201f16102e057600080fd5b50506102c05160206001820306601f82010390506103206102c0516008818352015b826103205111156103125761032e565b6000610320516102e001535b8151600101808352811415610302575b50505060206102a05260406102c0510160206001820306601f8201039050610280525b6000610280511115156103635761037f565b602061028051036102a001516020610280510361028052610351565b610160515650005b63863a311b60005114156106185734156103a057600080fd5b6000610140526101405161016052600354610180526101a060006020818352015b60016001610180511614156104425760006101a051602081106103e357600080fd5b600260c052602060c02001546020826102400101526020810190506101605160208261024001015260208101905080610240526102409050602060c0825160208401600060025af161043457600080fd5b60c0519050610160526104b0565b6000610160516020826101c00101526020810190506101a0516020811061046857600080fd5b600160c052602060c02001546020826101c0010152602081019050806101c0526101c09050602060c0825160208401600060025af16104a657600080fd5b60c0519050610160525b61018060026104be57600080fd5b60028151048152505b81516001018083528114156103c1575b505060006101605160208261044001015260208101905061014051610160516101805163806732896102c0526003546102e0526102e051600658016101ab565b506103405260006103a0525b6103405160206001820306601f82010390506103a0511015156105455761055e565b6103a05161036001526103a0516020016103a052610523565b61018052610160526101405261034060088060208461044001018260208501600060046012f150508051820191505060006018602082066103c001602082840111156105a957600080fd5b6020806103e082610140600060046015f150508181528090509050905060188060208461044001018260208501600060046014f150508051820191505080610440526104409050602060c0825160208401600060025af161060957600080fd5b60c051905060005260206000f3005b63621fd130600051141561072a57341561063157600080fd5b6380673289610140526003546101605261016051600658016101ab565b506101c0526000610220525b6101c05160206001820306601f82010390506102205110151561067c57610695565b610220516101e00152610220516020016102205261065a565b6101c0805160200180610280828460006004600a8704601201f16106b857600080fd5b50506102805160206001820306601f82010390506102e0610280516008818352015b826102e05111156106ea57610706565b60006102e0516102a001535b81516001018083528114156106da575b5050506020610260526040610280510160206001820306601f8201039050610260f3005b63c47e300d600051141561128257606060046101403760506004356004016101a037603060043560040135111561076057600080fd5b604060243560040161022037602060243560040135111561078057600080fd5b60806044356004016102803760606044356004013511156107a057600080fd5b63ffffffff600354106107b257600080fd5b633b9aca0061034052610340516107c857600080fd5b610340513404610320526000546103205110156107e457600080fd5b60306101a051146107f457600080fd5b6020610220511461080457600080fd5b6060610280511461081457600080fd5b6101a0516101c0516101e05161020051610220516102405161026051610280516102a0516102c0516102e05161030051610320516103405161036051610380516103a05163806732896103c052610320516103e0526103e051600658016101ab565b506104405260006104a0525b6104405160206001820306601f82010390506104a0511015156108a4576108bd565b6104a05161046001526104a0516020016104a052610882565b6103a05261038052610360526103405261032052610300526102e0526102c0526102a05261028052610260526102405261022052610200526101e0526101c0526101a052610440805160200180610360828460006004600a8704601201f161092457600080fd5b50506101a0516101c0516101e05161020051610220516102405161026051610280516102a0516102c0516102e05161030051610320516103405161036051610380516103a0516103c0516103e05161040051610420516104405161046051610480516104a05163806732896104c0526003546104e0526104e051600658016101ab565b506105405260006105a0525b6105405160206001820306601f82010390506105a0511015156109d5576109ee565b6105a05161056001526105a0516020016105a0526109b3565b6104a05261048052610460526104405261042052610400526103e0526103c0526103a05261038052610360526103405261032052610300526102e0526102c0526102a05261028052610260526102405261022052610200526101e0526101c0526101a0526105408051602001806105c0828460006004600a8704601201f1610a7557600080fd5b505060a06106405261064051610680526101a08051602001806106405161068001828460006004600a8704601201f1610aad57600080fd5b505061064051610680015160206001820306601f8201039050610640516106800161062081516040818352015b8361062051101515610aeb57610b08565b6000610620516020850101535b8151600101808352811415610ada575b50505050602061064051610680015160206001820306601f820103905061064051010161064052610640516106a0526102208051602001806106405161068001828460006004600a8704601201f1610b5f57600080fd5b505061064051610680015160206001820306601f8201039050610640516106800161062081516020818352015b8361062051101515610b9d57610bba565b6000610620516020850101535b8151600101808352811415610b8c575b50505050602061064051610680015160206001820306601f820103905061064051010161064052610640516106c0526103608051602001806106405161068001828460006004600a8704601201f1610c1157600080fd5b505061064051610680015160206001820306601f8201039050610640516106800161062081516020818352015b8361062051101515610c4f57610c6c565b6000610620516020850101535b8151600101808352811415610c3e575b50505050602061064051610680015160206001820306601f820103905061064051010161064052610640516106e0526102808051602001806106405161068001828460006004600a8704601201f1610cc357600080fd5b505061064051610680015160206001820306601f8201039050610640516106800161062081516060818352015b8361062051101515610d0157610d1e565b6000610620516020850101535b8151600101808352811415610cf0575b50505050602061064051610680015160206001820306601f82010390506106405101016106405261064051610700526105c08051602001806106405161068001828460006004600a8704601201f1610d7557600080fd5b505061064051610680015160206001820306601f8201039050610640516106800161062081516020818352015b8361062051101515610db357610dd0565b6000610620516020850101535b8151600101808352811415610da2575b50505050602061064051610680015160206001820306601f8201039050610640510101610640527f649bbc62d0e31342afea4e5cd82d4049e7e1ee912fc0889aa790803be39038c561064051610680a160006107205260006101a06030806020846107e001018260208501600060046016f150508051820191505060006010602082066107600160208284011115610e6757600080fd5b60208061078082610720600060046015f15050818152809050905090506010806020846107e001018260208501600060046013f1505080518201915050806107e0526107e09050602060c0825160208401600060025af1610ec757600080fd5b60c0519050610740526000600060406020820661088001610280518284011115610ef057600080fd5b6060806108a0826020602088068803016102800160006004601bf1505081815280905090509050602060c0825160208401600060025af1610f3057600080fd5b60c0519050602082610a800101526020810190506000604060206020820661094001610280518284011115610f6457600080fd5b606080610960826020602088068803016102800160006004601bf1505081815280905090509050602080602084610a0001018260208501600060046015f150508051820191505061072051602082610a0001015260208101905080610a0052610a009050602060c0825160208401600060025af1610fe157600080fd5b60c0519050602082610a8001015260208101905080610a8052610a809050602060c0825160208401600060025af161101857600080fd5b60c0519050610860526000600061074051602082610b20010152602081019050610220602080602084610b2001018260208501600060046015f150508051820191505080610b2052610b209050602060c0825160208401600060025af161107e57600080fd5b60c0519050602082610ca00101526020810190506000610360600880602084610c2001018260208501600060046012f15050805182019150506000601860208206610ba001602082840111156110d357600080fd5b602080610bc082610720600060046015f1505081815280905090509050601880602084610c2001018260208501600060046014f150508051820191505061086051602082610c2001015260208101905080610c2052610c209050602060c0825160208401600060025af161114657600080fd5b60c0519050602082610ca001015260208101905080610ca052610ca09050602060c0825160208401600060025af161117d57600080fd5b60c0519050610b0052600380546001825401101561119a57600080fd5b6001815401815550600354610d2052610d4060006020818352015b60016001610d20511614156111ea57610b0051610d4051602081106111d957600080fd5b600260c052602060c020015561127e565b6000610d4051602081106111fd57600080fd5b600260c052602060c0200154602082610d60010152602081019050610b0051602082610d6001015260208101905080610d6052610d609050602060c0825160208401600060025af161124e57600080fd5b60c0519050610b0052610d20600261126557600080fd5b60028151048152505b81516001018083528114156111b5575b5050005b639890220b60005114156112b657341561129b57600080fd5b600060006000600030316004546000f16112b457600080fd5b005b631ea30fef60005114156112dc5734156112cf57600080fd5b60005460005260206000f3005b63eb8545ee60005114156113025734156112f557600080fd5b60035460005260206000f3005b638ba35cdf600051141561132857341561131b57600080fd5b60045460005260206000f3005b60006000fd")};

    InMemoryState db;
    IntraBlockState state{db};

    state.set_balance(0x0000000000000000000000000000000000000000_address, intx::from_string<intx::uint256>("0x01"));
    state.set_balance(sender_address, intx::from_string<intx::uint256>("0x70155dca4fd46a6b49"));
    state.set_nonce(sender_address, 0xb02);
    state.set_code(callee_address, callee_code);
    state.set_balance(callee_address, intx::from_string<intx::uint256>("0x1ab6f94d08a0800000"));
    state.set_nonce(callee_address, 0x1);

    EVM evm{block, state, kGoerliConfig};

    CallGasCostTracer tracer;
    evm.add_tracer(tracer);

    Transaction txn{};  // txn #0 in block 1'029'553, see https://goerli.etherscan.io/tx/0x81b9951cde95115515c6049382e8227dc9a96972793df7da814ab22cc62dd091
    txn.set_sender(sender_address);
    txn.to = callee_address;
    txn.data = ByteView{*from_hex("9890220b")};

    uint64_t gas{3'978'728};
    CallResult res{evm.execute(txn, gas)};
    CHECK(res.status == EVMC_SUCCESS);
    const auto& call_gas_cost = tracer.call_gas_cost();
    CHECK(call_gas_cost.size() == 1);
    // CHECK(call_gas_cost[0] == 7400);  // CALL gas cost resulting in silk rpcdaemon
    CHECK(call_gas_cost[0] == 9700);  // CALL gas cost expected according to erigon rpcdaemon
}

TEST_CASE("Get gas cost for CALL #2", "[core][execution]") {
    Block block{};
    block.header.number = 49'439;  // real block on MAINNET chain see https://etherscan.io/block/49439

    evmc::address sender_address{0xA1E4380A3B1f749673E270229993eE55F35663b4_address};

    evmc::address callee_address{0xCde4DE4d3baa9f2CB0253DE1b86271152fBf7864_address};
    // The callee code.
    Bytes callee_code{*from_hex("60606040526000357c01000000000000000000000000000000000000000000000000000000009004806341c0e1b51461004f578063cfae32171461005c578063f1eae25c146100d55761004d565b005b61005a600450610110565b005b6100676004506101a4565b60405180806020018281038252838181518152602001915080519060200190808383829060006004602084601f0104600302600f01f150905090810190601f1680156100c75780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b6100e06004506100e2565b005b33600060006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908302179055505b565b600060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614156101a157600060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16ff5b5b565b60206040519081016040528060008152602001506001600050805480601f0160208091040260200160405190810160405280929190818152602001828054801561021357820191906000526020600020905b8154815290600101906020018083116101f657829003601f168201915b5050505050905061021f565b9056")};

    InMemoryState db;
    IntraBlockState state{db};

    state.set_balance(0x0000000000000000000000000000000000000000_address, intx::from_string<intx::uint256>("0x01"));
    state.set_balance(sender_address, intx::from_string<intx::uint256>("0x6B8CE05A2192D9D381"));
    state.set_nonce(sender_address, 0xb02);
    state.set_code(callee_address, callee_code);
    state.set_balance(callee_address, intx::from_string<intx::uint256>("0x1ab6f94d08a0800000"));
    state.set_nonce(callee_address, 0x1);

    EVM evm{block, state, kMainnetConfig};

    CallGasCostTracer tracer;
    evm.add_tracer(tracer);

    Transaction txn{};  // txn #0 in block 1'029'553, see https://goerli.etherscan.io/tx/0x81b9951cde95115515c6049382e8227dc9a96972793df7da814ab22cc62dd091
    txn.set_sender(sender_address);
    txn.to = callee_address;
    txn.data = ByteView{*from_hex("cfae3217")};

    uint64_t gas{3'978'728};
    CallResult res{evm.execute(txn, gas)};
    CHECK(res.status == EVMC_SUCCESS);
    const auto& call_gas_cost = tracer.call_gas_cost();
    CHECK(call_gas_cost.size() == 1);
    // CHECK(call_gas_cost[0] == 7400);  // CALL gas cost resulting in silk rpcdaemon
    CHECK(call_gas_cost[0] == 25055);  // CALL gas cost expected according to erigon rpcdaemon
}
}  // namespace silkworm
