/*
   Copyright 2020-2021 The Silkworm Authors

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
#include <silkworm/state/memory_buffer.hpp>

#include "address.hpp"
#include "execution.hpp"

namespace silkworm {

TEST_CASE("Zero gas price") {
    using Catch::Message;

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
        *from_hex("0x6060604052610922806100126000396000f3606060405236156100b6576000357c01000000000000000000"
                  "000000000000000000000000000000000000009004806317e7dd22146100bb5780633562fd20146100ee5780"
                  "633eba9ed21461011457806344bfa56e1461013a5780634c77e5ba146101c35780635a2bf25a1461020a5780"
                  "639007127b14610230578063a209a29c14610261578063a77aa49e146102ea578063bdc963d8146103105780"
                  "63c9a52d2c14610341578063f5866066146103a5576100b6565b610002565b34610002576100d66004808035"
                  "906020019091905050610409565b60405180821515815260200191505060405180910390f35b346100025761"
                  "0112600480803590602001909190803590602001909190505061043f565b005b346100025761013860048080"
                  "35906020019091908035906020019091905050610466565b005b346100025761015560048080359060200190"
                  "919050506104c0565b6040518080602001828103825283818151815260200191508051906020019080838382"
                  "9060006004602084601f0104600302600f01f150905090810190601f1680156101b557808203805160018360"
                  "20036101000a031916815260200191505b509250505060405180910390f35b34610002576101de6004808035"
                  "906020019091905050610596565b604051808273ffffffffffffffffffffffffffffffffffffffff16815260"
                  "200191505060405180910390f35b346100025761022e60048080359060200190919080359060200190919050"
                  "506105df565b005b346100025761024b6004808035906020019091905050610639565b604051808281526020"
                  "0191505060405180910390f35b346100025761027c6004808035906020019091905050610665565b60405180"
                  "806020018281038252838181518152602001915080519060200190808383829060006004602084601f010460"
                  "0302600f01f150905090810190601f1680156102dc5780820380516001836020036101000a03191681526020"
                  "0191505b509250505060405180910390f35b346100025761030e600480803590602001909190803590602001"
                  "909190505061073b565b005b346100025761032b6004808035906020019091905050610762565b6040518082"
                  "815260200191505060405180910390f35b34610002576103a360048080359060200190919080359060200190"
                  "82018035906020019191908080601f0160208091040260200160405190810160405280939291908181526020"
                  "0183838082843782019150505050505090909190505061078e565b005b346100025761040760048080359060"
                  "20019091908035906020019082018035906020019191908080601f0160208091040260200160405190810160"
                  "40528093929190818152602001838380828437820191505050505050909091905050610858565b005b600060"
                  "0460005060008360001916815260200190815260200160002060009054906101000a900460ff16905061043a"
                  "565b919050565b806000600050600084600019168152602001908152602001600020600050819055505b5050"
                  "565b80600460005060008460001916815260200190815260200160002060006101000a81548160ff02191690"
                  "837f01000000000000000000000000000000000000000000000000000000000000009081020402179055505b"
                  "5050565b60206040519081016040528060008152602001506003600050600083600019168152602001908152"
                  "6020016000206000508054600181600116156101000203166002900480601f01602080910402602001604051"
                  "9081016040528092919081815260200182805460018160011615610100020316600290048015610585578060"
                  "1f1061055a57610100808354040283529160200191610585565b820191906000526020600020905b81548152"
                  "906001019060200180831161056857829003601f168201915b50505050509050610591565b919050565b6000"
                  "600260005060008360001916815260200190815260200160002060009054906101000a900473ffffffffffff"
                  "ffffffffffffffffffffffffffff1690506105da565b919050565b8060026000506000846000191681526020"
                  "0190815260200160002060006101000a81548173ffffffffffffffffffffffffffffffffffffffff02191690"
                  "836c010000000000000000000000009081020402179055505b5050565b600060056000506000836000191681"
                  "52602001908152602001600020600050549050610660565b919050565b602060405190810160405280600081"
                  "5260200150600160005060008360001916815260200190815260200160002060005080546001816001161561"
                  "01000203166002900480601f0160208091040260200160405190810160405280929190818152602001828054"
                  "6001816001161561010002031660029004801561072a5780601f106106ff5761010080835404028352916020"
                  "019161072a565b820191906000526020600020905b81548152906001019060200180831161070d5782900360"
                  "1f168201915b50505050509050610736565b919050565b806005600050600084600019168152602001908152"
                  "602001600020600050819055505b5050565b6000600060005060008360001916815260200190815260200160"
                  "0020600050549050610789565b919050565b8060036000506000846000191681526020019081526020016000"
                  "206000509080519060200190828054600181600116156101000203166002900490600052602060002090601f"
                  "016020900481019282601f106107f557805160ff1916838001178555610826565b8280016001018555821561"
                  "0826579182015b82811115610825578251826000505591602001919060010190610807565b5b509050610851"
                  "9190610833565b8082111561084d5760008181506000905550600101610833565b5090565b50505b5050565b"
                  "8060016000506000846000191681526020019081526020016000206000509080519060200190828054600181"
                  "600116156101000203166002900490600052602060002090601f016020900481019282601f106108bf578051"
                  "60ff19168380011785556108f0565b828001600101855582156108f0579182015b828111156108ef57825182"
                  "60005055916020019190600101906108d1565b5b50905061091b91906108fd565b8082111561091757600081"
                  "815060009055506001016108fd565b5090565b50505b505056"),
    };

    MemoryBuffer db;
    IntraBlockState state{db};
    ExecutionProcessor processor{block, state, kMainnetConfig};

    CHECK(processor.validate_transaction(txn) == ValidationResult::kMissingSender);

    txn.from = sender;
    Receipt receipt{processor.execute_transaction(txn)};
    CHECK(receipt.success);
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

    MemoryBuffer db;
    IntraBlockState state{db};
    ExecutionProcessor processor{block, state, kMainnetConfig};

    Transaction txn{
        Transaction::Type::kLegacy,  // type
        nonce,                       // nonce
        0,                           // max_priority_fee_per_gas
        59 * kGiga,                  // max_fee_per_gas
        103'858,                     // gas_limit
        {},                          // to
        0,                           // value
        code,                        // data
    };

    state.add_to_balance(caller, kEther);
    state.set_nonce(caller, nonce);
    txn.from = caller;

    Receipt receipt1{processor.execute_transaction(txn)};
    CHECK(receipt1.success);

    // Call the newly created contract
    txn.nonce = nonce + 1;
    txn.to = create_address(caller, nonce);

    // It should run SSTORE(0,0) with a potential refund
    txn.data.clear();

    // But then there's not enough gas for the BALANCE operation
    txn.gas_limit = fee::kGTransaction + 5'020;

    Receipt receipt2{processor.execute_transaction(txn)};
    CHECK(!receipt2.success);
    CHECK(receipt2.cumulative_gas_used - receipt1.cumulative_gas_used == txn.gas_limit);
}

TEST_CASE("Self-destruct") {
    Block block{};
    block.header.number = 1'487'375;
    block.header.gas_limit = 4'712'388;
    block.header.beneficiary = 0x61c808d82a3ac53231750dadc13c777b59310bd9_address;
    evmc::address suicidal_address{0x6d20c1c07e56b7098eb8c50ee03ba0f6f498a91d_address};
    evmc::address caller_address{0x4bf2054ffae7a454a35fd8cf4be21b23b1f25a6f_address};

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

    MemoryBuffer db;
    IntraBlockState state{db};
    ExecutionProcessor processor{block, state, kMainnetConfig};

    state.add_to_balance(caller_address, kEther);
    state.set_code(caller_address, caller_code);
    state.set_code(suicidal_address, suicidal_code);

    Transaction txn{
        Transaction::Type::kLegacy,  // type
        0,                           // nonce
        0,                           // max_priority_fee_per_gas
        20 * kGiga,                  // max_fee_per_gas
        100'000,                     // gas_limit
        caller_address,              // to
        0,                           // value
    };
    txn.from = caller_address;

    evmc::bytes32 address_as_hash{to_bytes32(full_view(suicidal_address))};
    txn.data = full_view(address_as_hash);

    Receipt receipt1{processor.execute_transaction(txn)};
    CHECK(receipt1.success);

    CHECK(!state.exists(suicidal_address));

    // Now the contract is self-destructed, this is a simple value transfer
    txn.nonce = 1;
    txn.to = suicidal_address;
    txn.data.clear();

    Receipt receipt2{processor.execute_transaction(txn)};
    CHECK(receipt2.success);

    CHECK(state.exists(suicidal_address));
    CHECK(state.get_balance(suicidal_address) == 0);

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

    MemoryBuffer buffer;

    // Some funds were previously transferred to the address:
    // https://etherscan.io/address/0x78c65b078353a8c4ce58fb4b5acaac6042d591d5
    Account account{};
    account.balance = 66'252'368 * kGiga;
    buffer.update_account(address, std::nullopt, account);

    Transaction txn{
        Transaction::Type::kLegacy,  // type
        nonce,                       // nonce
        0,                           // max_priority_fee_per_gas
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
                  "99c426b2a0453e27decaecd93c3722fb0f378fc5"),
    };
    txn.from = caller;

    IntraBlockState state{buffer};
    state.add_to_balance(caller, kEther);

    ExecutionProcessor processor{block, state, kMainnetConfig};

    Receipt receipt{processor.execute_transaction(txn)};
    // out of gas
    CHECK(!receipt.success);

    state.write_to_db(block_number);

    // only the caller and the miner should change
    CHECK(buffer.read_account(address) == account);
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
        0,                           // max_priority_fee_per_gas
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
                  "0060006000604051620249f0f15061000080610108600039610108565b6000f3"),
    };
    txn.from = caller;

    MemoryBuffer db;
    IntraBlockState state{db};
    state.add_to_balance(caller, kEther);

    ExecutionProcessor processor{block, state, kMainnetConfig};

    Receipt receipt{processor.execute_transaction(txn)};
    CHECK(receipt.success);

    state.write_to_db(block_number);

    // suicide_beneficiary should've been touched and deleted
    CHECK(!db.read_account(suicide_beneficiary).has_value());
}

}  // namespace silkworm
