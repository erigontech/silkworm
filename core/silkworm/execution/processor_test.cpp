/*
   Copyright 2020-2022 The Silkworm Authors

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

#include "processor.hpp"

#include <catch2/catch.hpp>
#include <evmc/evmc.hpp>

#include <silkworm/chain/protocol_param.hpp>
#include <silkworm/common/test_util.hpp>
#include <silkworm/consensus/ethash/engine.hpp>
#include <silkworm/state/in_memory_state.hpp>

#include "address.hpp"

namespace silkworm {

TEST_CASE("Zero gas price") {
    Block block{};
    block.header.number = 2'687'232;
    block.header.gas_limit = 3'303'221;
    block.header.beneficiary = 0x4bb96091ee9d802ed039c4d1a5f6216f90f81b01_address;

    // The sender does not exist
    evmc::address sender{0x004512399a230565b99be5c3b0030a56f3ace68c_address};

    Transaction txn{
        Transaction::Type::kLegacy,  // type
        0,                           // nonce
        0,                           // max_priority_fee_per_gas
        0,                           // max_fee_per_gas
        764'017,                     // gas_limit
        {},                          // to
        0,                           // value
        *from_hex("0x606060"),       // data
        false,                       // odd_y_parity
        std::nullopt,                // chain_id
        1,                           // r
        1,                           // s
    };

    InMemoryState state;
    auto engine{consensus::engine_factory(kMainnetConfig)};
    ExecutionProcessor processor{block, *engine, state, kMainnetConfig};

    CHECK(processor.validate_transaction(txn) == ValidationResult::kMissingSender);

    txn.from = sender;
    Receipt receipt;
    processor.execute_transaction(txn, receipt);
    CHECK(receipt.success);
}

TEST_CASE("EIP-3607: Reject transactions from senders with deployed code") {
    Block block{};
    block.header.number = 1;
    block.header.gas_limit = 3'000'000;

    const evmc::address sender{0x71562b71999873DB5b286dF957af199Ec94617F7_address};

    Transaction txn{test::sample_transactions()[0]};
    txn.nonce = 0;
    txn.from = sender;

    InMemoryState state;
    auto engine{consensus::engine_factory(kMainnetConfig)};
    ExecutionProcessor processor{block, *engine, state, kMainnetConfig};

    processor.evm().state().add_to_balance(sender, 10 * kEther);
    processor.evm().state().set_code(sender, *from_hex("B0B0FACE"));

    CHECK(processor.validate_transaction(txn) == ValidationResult::kSenderNoEOA);
}

TEST_CASE("No refund on error") {
    Block block{};
    block.header.number = 10'050'107;
    block.header.gas_limit = 328'646;
    block.header.beneficiary = 0x5146556427ff689250ed1801a783d12138c3dd5e_address;
    evmc::address caller{0x834e9b529ac9fa63b39a06f8d8c9b0d6791fa5df_address};
    uint64_t nonce{3};

    // This contract initially sets its 0th storage to 0x2a.
    // When called, it updates the 0th storage to the input provided.
    Bytes code{*from_hex("602a60005560098060106000396000f36000358060005531")};
    /* https://github.com/CoinCulture/evm-tools
    0      PUSH1  => 2a
    2      PUSH1  => 00
    4      SSTORE
    5      PUSH1  => 09
    7      DUP1
    8      PUSH1  => 10
    10     PUSH1  => 00
    12     CODECOPY
    13     PUSH1  => 00
    15     RETURN
  -----------------------------
    16     PUSH1  => 00
    18     CALLDATALOAD
    19     DUP1
    20     PUSH1  => 00
    22     SSTORE
    23     BALANCE
    */

    InMemoryState state;
    auto engine{consensus::engine_factory(kMainnetConfig)};
    ExecutionProcessor processor{block, *engine, state, kMainnetConfig};

    Transaction txn{
        Transaction::Type::kLegacy,  // type
        nonce,                       // nonce
        59 * kGiga,                  // max_priority_fee_per_gas
        59 * kGiga,                  // max_fee_per_gas
        103'858,                     // gas_limit
        {},                          // to
        0,                           // value
        code,                        // data
        false,                       // odd_y_parity
        std::nullopt,                // chain_id
        1,                           // r
        1,                           // s
    };

    processor.evm().state().add_to_balance(caller, kEther);
    processor.evm().state().set_nonce(caller, nonce);
    txn.from = caller;

    Receipt receipt1;
    processor.execute_transaction(txn, receipt1);
    CHECK(receipt1.success);

    // Call the newly created contract
    txn.nonce = nonce + 1;
    txn.to = create_address(caller, nonce);

    // It should run SSTORE(0,0) with a potential refund
    txn.data.clear();

    // But then there's not enough gas for the BALANCE operation
    txn.gas_limit = fee::kGTransaction + 5'020;

    Receipt receipt2;
    processor.execute_transaction(txn, receipt2);
    CHECK(!receipt2.success);
    CHECK(receipt2.cumulative_gas_used - receipt1.cumulative_gas_used == txn.gas_limit);
}

TEST_CASE("Self-destruct") {
    Block block{};
    block.header.number = 1'487'375;
    block.header.gas_limit = 4'712'388;
    block.header.beneficiary = 0x61c808d82a3ac53231750dadc13c777b59310bd9_address;

    const evmc::address suicidal_address{0x6d20c1c07e56b7098eb8c50ee03ba0f6f498a91d_address};
    const evmc::address caller_address{0x4bf2054ffae7a454a35fd8cf4be21b23b1f25a6f_address};
    const evmc::address originator{0x5a0b54d5dc17e0aadc383d2db43b0a0d3e029c4c_address};

    // The contract self-destructs if called with zero value.
    Bytes suicidal_code{*from_hex("346007576000ff5b")};
    /* https://github.com/CoinCulture/evm-tools
    0      CALLVALUE
    1      PUSH1  => 07
    3      JUMPI
    4      PUSH1  => 00
    6      SUICIDE
    7      JUMPDEST
    */

    // The caller calls the input contract three times:
    // twice with zero value and once with non-zero value.
    Bytes caller_code{*from_hex("600080808080803561eeeef150600080808080803561eeeef15060008080806005813561eeeef1")};
    /* https://github.com/CoinCulture/evm-tools
    0      PUSH1  => 00
    2      DUP1
    3      DUP1
    4      DUP1
    5      DUP1
    6      DUP1
    7      CALLDATALOAD
    8      PUSH2  => eeee
    11     CALL
    12     POP
    13     PUSH1  => 00
    15     DUP1
    16     DUP1
    17     DUP1
    18     DUP1
    19     DUP1
    20     CALLDATALOAD
    21     PUSH2  => eeee
    24     CALL
    25     POP
    26     PUSH1  => 00
    28     DUP1
    29     DUP1
    30     DUP1
    31     PUSH1  => 05
    33     DUP2
    34     CALLDATALOAD
    35     PUSH2  => eeee
    38     CALL
    */

    InMemoryState state;
    auto engine{consensus::engine_factory(kMainnetConfig)};
    ExecutionProcessor processor{block, *engine, state, kMainnetConfig};

    processor.evm().state().add_to_balance(originator, kEther);
    processor.evm().state().set_code(caller_address, caller_code);
    processor.evm().state().set_code(suicidal_address, suicidal_code);

    Transaction txn{
        Transaction::Type::kLegacy,  // type
        0,                           // nonce
        20 * kGiga,                  // max_priority_fee_per_gas
        20 * kGiga,                  // max_fee_per_gas
        100'000,                     // gas_limit
        caller_address,              // to
        0,                           // value
        {},                          // data
        false,                       // odd_y_parity
        std::nullopt,                // chain_id
        1,                           // r
        1,                           // s
    };
    txn.from = originator;

    evmc::bytes32 address_as_hash{to_bytes32(suicidal_address)};
    txn.data = ByteView{address_as_hash};

    Receipt receipt1;
    processor.execute_transaction(txn, receipt1);
    CHECK(receipt1.success);

    CHECK(!processor.evm().state().exists(suicidal_address));

    // Now the contract is self-destructed, this is a simple value transfer
    txn.nonce = 1;
    txn.to = suicidal_address;
    txn.data.clear();

    Receipt receipt2;
    processor.execute_transaction(txn, receipt2);
    CHECK(receipt2.success);

    CHECK(processor.evm().state().exists(suicidal_address));
    CHECK(processor.evm().state().get_balance(suicidal_address) == 0);

    CHECK(receipt2.cumulative_gas_used == receipt1.cumulative_gas_used + fee::kGTransaction);
}

TEST_CASE("Out of Gas during account re-creation") {
    uint64_t block_number{2'081'788};
    Block block{};
    block.header.number = block_number;
    block.header.gas_limit = 4'712'388;
    block.header.beneficiary = 0xa42af2c70d316684e57aefcc6e393fecb1c7e84e_address;
    evmc::address caller{0xc789e5aba05051b1468ac980e30068e19fad8587_address};

    uint64_t nonce{0};
    evmc::address address{create_address(caller, nonce)};

    InMemoryState state;

    // Some funds were previously transferred to the address:
    // https://etherscan.io/address/0x78c65b078353a8c4ce58fb4b5acaac6042d591d5
    Account account{};
    account.balance = 66'252'368 * kGiga;
    state.update_account(address, /*initial=*/std::nullopt, account);

    Transaction txn{
        Transaction::Type::kLegacy,  // type
        nonce,                       // nonce
        20 * kGiga,                  // max_priority_fee_per_gas
        20 * kGiga,                  // max_fee_per_gas
        690'000,                     // gas_limit
        {},                          // to
        0,                           // value
        *from_hex("0x6060604052604051610ca3380380610ca3833981016040528080518201919060200150505b600281511015"
                  "61003357610002565b8060006000509080519060200190828054828255906000526020600020908101928215"
                  "6100a4579160200282015b828111156100a35782518260006101000a81548173ffffffffffffffffffffffff"
                  "ffffffffffffffff0219169083021790555091602001919060010190610061565b5b5090506100eb91906100"
                  "b1565b808211156100e757600081816101000a81549073ffffffffffffffffffffffffffffffffffffffff02"
                  "19169055506001016100b1565b5090565b50506000600160006101000a81548160ff02191690830217905550"
                  "5b50610b8d806101166000396000f360606040523615610095576000357c0100000000000000000000000000"
                  "000000000000000000000000000000900480632079fb9a14610120578063391252151461016257806345550a"
                  "51146102235780637df73e27146102ac578063979f1976146102da578063a0b7967b14610306578063a68a76"
                  "cc14610329578063abe3219c14610362578063fc0f392d1461038757610095565b61011e5b60003411156101"
                  "1b577f6e89d517057028190560dd200cf6bf792842861353d1173761dfa362e1c133f0333460003660405180"
                  "8573ffffffffffffffffffffffffffffffffffffffff16815260200184815260200180602001828103825284"
                  "848281815260200192508082843782019150509550505050505060405180910390a15b5b565b005b61013660"
                  "04808035906020019091905050610396565b604051808273ffffffffffffffffffffffffffffffffffffffff"
                  "16815260200191505060405180910390f35b6102216004808035906020019091908035906020019091908035"
                  "906020019082018035906020019191908080601f016020809104026020016040519081016040528093929190"
                  "8181526020018383808284378201915050505050509090919080359060200190919080359060200190919080"
                  "35906020019082018035906020019191908080601f0160208091040260200160405190810160405280939291"
                  "908181526020018383808284378201915050505050509090919050506103d8565b005b610280600480803590"
                  "6020019091908035906020019082018035906020019191908080601f01602080910402602001604051908101"
                  "604052809392919081815260200183838082843782019150505050505090909190505061064b565b60405180"
                  "8273ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b6102c260"
                  "048080359060200190919050506106fa565b60405180821515815260200191505060405180910390f35b6102"
                  "f060048080359060200190919050506107a8565b6040518082815260200191505060405180910390f35b6103"
                  "136004805050610891565b6040518082815260200191505060405180910390f35b6103366004805050610901"
                  "565b604051808273ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390"
                  "f35b61036f600480505061093b565b60405180821515815260200191505060405180910390f35b6103946004"
                  "80505061094e565b005b600060005081815481101561000257906000526020600020900160005b9150909054"
                  "906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b600060006103e5336106fa56"
                  "5b15156103f057610002565b600160009054906101000a900460ff1680156104125750610410886106fa565b"
                  "155b1561041c57610002565b4285101561042957610002565b610432846107a8565b50878787878760405180"
                  "8673ffffffffffffffffffffffffffffffffffffffff166c0100000000000000000000000002815260140185"
                  "81526020018480519060200190808383829060006004602084601f0104600f02600301f15090500183815260"
                  "200182815260200195505050505050604051809103902091506104b7828461064b565b90506104c2816106fa"
                  "565b15156104cd57610002565b3373ffffffffffffffffffffffffffffffffffffffff168173ffffffffffff"
                  "ffffffffffffffffffffffffffff16141561050657610002565b8773ffffffffffffffffffffffffffffffff"
                  "ffffffff16600088604051809050600060405180830381858888f19350505050151561054357610002565b7f"
                  "59bed9ab5d78073465dd642a9e3e76dfdb7d53bcae9d09df7d0b8f5234d5a8063382848b8b8b604051808773"
                  "ffffffffffffffffffffffffffffffffffffffff1681526020018673ffffffffffffffffffffffffffffffff"
                  "ffffffff168152602001856000191681526020018473ffffffffffffffffffffffffffffffffffffffff1681"
                  "5260200183815260200180602001828103825283818151815260200191508051906020019080838382906000"
                  "6004602084601f0104600f02600301f150905090810190601f16801561062e57808203805160018360200361"
                  "01000a031916815260200191505b5097505050505050505060405180910390a15b5050505050505050565b60"
                  "006000600060006041855114151561066357610002565b602085015192506040850151915060ff6041860151"
                  "169050601b8160ff16101561069057601b8101905080505b6001868285856040518085600019168152602001"
                  "8460ff1681526020018360001916815260200182600019168152602001945050505050602060405180830381"
                  "6000866161da5a03f1156100025750506040518051906020015093506106f1565b50505092915050565b6000"
                  "6000600090505b600060005080549050811015610799578273ffffffffffffffffffffffffffffffffffffff"
                  "ff16600060005082815481101561000257906000526020600020900160005b9054906101000a900473ffffff"
                  "ffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1614156107"
                  "8b57600191506107a2565b5b8080600101915050610703565b600091506107a2565b50919050565b60006000"
                  "60006107b7336106fa565b15156107c257610002565b60009150600090505b600a8160ff16101561084b5783"
                  "60026000508260ff16600a8110156100025790900160005b505414156107fd57610002565b60026000508260"
                  "0a8110156100025790900160005b505460026000508260ff16600a8110156100025790900160005b50541015"
                  "61083d578060ff16915081505b5b80806001019150506107cb565b600260005082600a811015610002579090"
                  "0160005b505484101561086e57610002565b83600260005083600a8110156100025790900160005b50819055"
                  "505b5050919050565b60006000600060009150600090505b600a8110156108f15781600260005082600a8110"
                  "156100025790900160005b505411156108e357600260005081600a8110156100025790900160005b50549150"
                  "81505b5b80806001019150506108a0565b6001820192506108fc565b505090565b600061090c336106fa565b"
                  "151561091757610002565b6040516101c2806109cb833901809050604051809103906000f09050610938565b"
                  "90565b600160009054906101000a900460ff1681565b610957336106fa565b151561096257610002565b6001"
                  "600160006101000a81548160ff021916908302179055507f0909e8f76a4fd3e970f2eaef56c0ee6dfaf8b87c"
                  "5b8d3f56ffce78e825a9115733604051808273ffffffffffffffffffffffffffffffffffffffff1681526020"
                  "0191505060405180910390a15b5660606040525b33600060006101000a81548173ffffffffffffffffffffff"
                  "ffffffffffffffffff021916908302179055505b6101838061003f6000396000f36060604052361561004857"
                  "6000357c0100000000000000000000000000000000000000000000000000000000900480636b9f96ea146100"
                  "a6578063ca325469146100b557610048565b6100a45b600060009054906101000a900473ffffffffffffffff"
                  "ffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16600034604051809050"
                  "600060405180830381858888f19350505050505b565b005b6100b360048050506100ee565b005b6100c26004"
                  "80505061015d565b604051808273ffffffffffffffffffffffffffffffffffffffff16815260200191505060"
                  "405180910390f35b600060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673"
                  "ffffffffffffffffffffffffffffffffffffffff1660003073ffffffffffffffffffffffffffffffffffffff"
                  "ff1631604051809050600060405180830381858888f19350505050505b565b600060009054906101000a9004"
                  "73ffffffffffffffffffffffffffffffffffffffff1681560000000000000000000000000000000000000000"
                  "0000000000000000000000200000000000000000000000000000000000000000000000000000000000000002"
                  "000000000000000000000000c789e5aba05051b1468ac980e30068e19fad8587000000000000000000000000"
                  "99c426b2a0453e27decaecd93c3722fb0f378fc5"),  // data
        false,                                                  // odd_y_parity
        std::nullopt,                                           // chain_id
        1,                                                      // r
        1,                                                      // s
    };
    txn.from = caller;

    auto engine{consensus::engine_factory(kMainnetConfig)};
    ExecutionProcessor processor{block, *engine, state, kMainnetConfig};
    processor.evm().state().add_to_balance(caller, kEther);

    Receipt receipt;
    processor.execute_transaction(txn, receipt);
    // out of gas
    CHECK(!receipt.success);

    processor.evm().state().write_to_db(block_number);

    // only the caller and the miner should change
    CHECK(state.read_account(address) == account);
}

TEST_CASE("Empty suicide beneficiary") {
    uint64_t block_number{2'687'389};
    Block block{};
    block.header.number = block_number;
    block.header.gas_limit = 4'712'388;
    block.header.beneficiary = 0x2a65aca4d5fc5b5c859090a6c34d164135398226_address;
    evmc::address caller{0x5ed8cee6b63b1c6afce3ad7c92f4fd7e1b8fad9f_address};
    evmc::address suicide_beneficiary{0xee098e6c2a43d9e2c04f08f0c3a87b0ba59079d5_address};

    Transaction txn{
        Transaction::Type::kLegacy,  // type
        0,                           // nonce
        30 * kGiga,                  // max_priority_fee_per_gas
        30 * kGiga,                  // max_fee_per_gas
        360'000,                     // gas_limit
        {},                          // to
        0,                           // value
        *from_hex("0x6000607f5359610043806100135939610056566c010000000000000000000000007fee098e6c2"
                  "a43d9e2c04f08f0c3a87b0ba59079d4d53532071d6cd0cb86facd5605ff6100008061003f600039"
                  "61003f565b6000f35b816000f0905050596100718061006c59396100dd5661005f8061000e60003"
                  "961006d566000603f5359610043806100135939610056566c010000000000000000000000007fee"
                  "098e6c2a43d9e2c04f08f0c3a87b0ba59079d4d53532071d6cd0cb86facd5605ff6100008061003"
                  "f60003961003f565b6000f35b816000f0905050fe5b6000f35b816000f090506040526000600060"
                  "0060006000604051620249f0f15061000080610108600039610108565b6000f3"),  // data
        false,                                                                          // odd_y_parity
        std::nullopt,                                                                   // chain_id
        1,                                                                              // r
        1,                                                                              // s
    };
    txn.from = caller;

    InMemoryState state;

    auto engine{consensus::engine_factory(kMainnetConfig)};
    ExecutionProcessor processor{block, *engine, state, kMainnetConfig};
    processor.evm().state().add_to_balance(caller, kEther);

    Receipt receipt;
    processor.execute_transaction(txn, receipt);
    CHECK(receipt.success);

    processor.evm().state().write_to_db(block_number);

    // suicide_beneficiary should've been touched and deleted
    CHECK(!state.read_account(suicide_beneficiary).has_value());
}

}  // namespace silkworm
