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

    SECTION("destruct_send-funds_recreate_same_block") {
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
    }

    SECTION("destruct_send-funds_recreate_separate_block") {
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
            CHECK(state.get_current_storage(to, {}) == evmc::bytes32{});
            state.write_to_db(2);
            CHECK(state.get_current_storage(to, {}) == evmc::bytes32{});
            CHECK(db.state_root_hash() == 0x8e723de3b34ef0632b5421f0f8ad8dfa6c981e99009141b5b7130c790f0d38c6_bytes32);
        }
        {
            IntraBlockState state{db};

            // Finally, in the last block, recreate it: the storage location previously set to non-zero must be zeroed
            state.clear_journal_and_substate();
            CHECK(state.get_original_storage(to, {}) == evmc::bytes32{});
            CHECK(state.get_current_storage(to, {}) == evmc::bytes32{});
            state.create_contract(to);
            CHECK(state.get_original_storage(to, {}) == evmc::bytes32{});
            CHECK(state.get_current_storage(to, {}) == evmc::bytes32{});
            state.finalize_transaction(EVMC_SHANGHAI);
            state.write_to_db(3);
        }
    }

    // Post-conditions: account must have incarnation == 2 and storage location zeroed
    const auto contract_address = db.read_account(to);
    REQUIRE(contract_address);
    CHECK(contract_address->incarnation == 2);
    CHECK(db.read_storage(to, contract_address->incarnation, {}) == evmc::bytes32{0});
    CHECK(db.state_root_hash() == 0x8e723de3b34ef0632b5421f0f8ad8dfa6c981e99009141b5b7130c790f0d38c6_bytes32);
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
        result_ = {ValidationResult::kOk, res.status_code, gas_left, gas_refund, std::nullopt, {res.output_data, res.output_size}};
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

    bool execution_start_called() const { return execution_start_called_; }
    bool execution_end_called() const { return execution_end_called_; }
    bool creation_completed_called() const { return creation_completed_called_; }
    bool self_destruct_called() const { return self_destruct_called_; }
    const Bytes& bytecode() const { return bytecode_; }
    const evmc_revision& rev() const { return rev_; }
    const std::vector<evmc_message>& msg_stack() const { return msg_stack_; }
    const std::vector<uint32_t>& pc_stack() const { return pc_stack_; }
    const std::map<uint32_t, size_t>& memory_size_stack() const { return memory_size_stack_; }
    const std::map<uint32_t, evmc::bytes32>& storage_stack() const { return storage_stack_; }
    const CallResult& result() const { return result_; }

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
    std::map<uint32_t, size_t> memory_size_stack_;
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
    CHECK(tracer1.memory_size_stack() == std::map<uint32_t, size_t>{{0, 0}});
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
    CHECK(tracer2.memory_size_stack() == std::map<uint32_t, size_t>{{0, 0},
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
    CHECK(tracer3.memory_size_stack() == std::map<uint32_t, size_t>{{0, 0}, {2, 0}, {3, 0}, {5, 0}});
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
    static constexpr evmc::address kZeroAddress = 0x0000000000000000000000000000000000000000_address;
    const evmc::address caller{0x0a6bb546b9208cfab9e8fa2b9b2c042b18df7030_address};
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
        CHECK(!account_changes.contains(kZeroAddress));      // destruction beneficiary receives zero balance (hence unchanged)
        CHECK(!account_changes.contains(contract_address));  // contract address hasn't changed after all
    }
    CHECK(state.number_of_self_destructs() == 1);
}

// First occurrence at mainnet block 1'639'553
TEST_CASE("Missing sender in call traces for DELEGATECALL", "[core][execution]") {
    static constexpr evmc::address kZeroAddress = 0x0000000000000000000000000000000000000000_address;
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
    CHECK(call_traces.recipients.contains(kZeroAddress));    // 1st+2nd txs go to zero_address (contract creation)
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

}  // namespace silkworm
