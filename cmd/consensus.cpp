/*
   Copyright 2020 The Silkworm Authors

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

#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <nlohmann/json.hpp>
#include <silkworm/chain/block_chain.hpp>
#include <silkworm/common/util.hpp>
#include <silkworm/execution/processor.hpp>
#include <silkworm/rlp/decode.hpp>
#include <silkworm/state/intra_block_state.hpp>
#include <silkworm/types/block.hpp>
#include <string>
#include <string_view>

// See https://ethereum-tests.readthedocs.io/en/latest/test_types/blockchain_tests.html

using namespace silkworm;

namespace fs = std::filesystem;

static const fs::path kRootDir{SILKWORM_CONSENSUS_TEST_DIR};

static const fs::path kBlockchainDir{kRootDir / "BlockchainTests"};

static const std::set<fs::path> kSlowTests{
    kBlockchainDir / "GeneralStateTests" / "stTimeConsuming",
};

// TODO[Issue #23] make the failing tests work
static const std::set<fs::path> kFailingTests{
    kBlockchainDir / "InvalidBlocks",

    // Expected: "UnknownParent"
    kBlockchainDir / "TransitionTests" / "bcFrontierToHomestead" / "HomesteadOverrideFrontier.json",

    // forks are not supported yet
    kBlockchainDir / "TransitionTests" / "bcFrontierToHomestead" /
        "blockChainFrontierWithLargerTDvsHomesteadBlockchain.json",
    kBlockchainDir / "TransitionTests" / "bcFrontierToHomestead" /
        "blockChainFrontierWithLargerTDvsHomesteadBlockchain2.json",
    kBlockchainDir / "ValidBlocks" / "bcForkStressTest" / "ForkStressTest.json",
    kBlockchainDir / "ValidBlocks" / "bcGasPricerTest" / "RPC_API_Test.json",
    kBlockchainDir / "ValidBlocks" / "bcMultiChainTest",
    kBlockchainDir / "ValidBlocks" / "bcTotalDifficultyTest",
};

static constexpr size_t kColumnWidth{70};

static const std::map<std::string, silkworm::ChainConfig> kNetworkConfig{
    {"Frontier",
     {
         1,  // chain_id
     }},
    {"Homestead",
     {
         1,  // chain_id
         0,  // homestead_block
     }},
    {"EIP150",
     {
         1,  // chain_id
         0,  // homestead_block
         0,  // tangerine_whistle_block
     }},
    {"EIP158",
     {
         1,  // chain_id
         0,  // homestead_block
         0,  // tangerine_whistle_block
         0,  // spurious_dragon_block
     }},
    {"Byzantium",
     {
         1,  // chain_id
         0,  // homestead_block
         0,  // tangerine_whistle_block
         0,  // spurious_dragon_block
         0,  // byzantium_block
     }},
    {"Constantinople",
     {
         1,  // chain_id
         0,  // homestead_block
         0,  // tangerine_whistle_block
         0,  // spurious_dragon_block
         0,  // byzantium_block
         0,  // constantinople_block
     }},
    {"ConstantinopleFix",
     {
         1,  // chain_id
         0,  // homestead_block
         0,  // tangerine_whistle_block
         0,  // spurious_dragon_block
         0,  // byzantium_block
         0,  // constantinople_block
         0,  // petersburg_block
     }},
    {"Istanbul",
     {
         1,  // chain_id
         0,  // homestead_block
         0,  // tangerine_whistle_block
         0,  // spurious_dragon_block
         0,  // byzantium_block
         0,  // constantinople_block
         0,  // petersburg_block
         0,  // istanbul_block
     }},
    {"FrontierToHomesteadAt5",
     {
         1,  // chain_id
         5,  // homestead_block
     }},
    {"HomesteadToEIP150At5",
     {
         1,  // chain_id
         0,  // homestead_block
         5,  // tangerine_whistle_block
     }},
    {"HomesteadToDaoAt5",
     {
         1,   // chain_id
         0,   // homestead_block
         {},  // tangerine_whistle_block
         {},  // spurious_dragon_block
         {},  // byzantium_block
         {},  // constantinople_block
         {},  // petersburg_block
         {},  // istanbul_block
         {},  // muir_glacier_block
         5,   // dao_block
     }},
    {"EIP158ToByzantiumAt5",
     {
         1,  // chain_id
         0,  // homestead_block
         0,  // tangerine_whistle_block
         0,  // spurious_dragon_block
         5,  // byzantium_block
     }},
    {"ByzantiumToConstantinopleFixAt5",
     {
         1,  // chain_id
         0,  // homestead_block
         0,  // tangerine_whistle_block
         0,  // spurious_dragon_block
         0,  // byzantium_block
         5,  // constantinople_block
         5,  // petersburg_block
     }},
};

IntraBlockState pre_state(const nlohmann::json& pre) {
  IntraBlockState state{nullptr};

  for (const auto& entry : pre.items()) {
    evmc::address address{to_address(from_hex(entry.key()))};
    const nlohmann::json& account{entry.value()};
    Bytes balance{from_hex(account["balance"].get<std::string>())};
    state.set_balance(address, rlp::read_uint256(balance, /*allow_leading_zeros=*/true));
    state.set_code(address, from_hex(account["code"].get<std::string>()));
    Bytes nonce{from_hex(account["nonce"].get<std::string>())};
    state.set_nonce(address, rlp::read_uint64(nonce, /*allow_leading_zeros=*/true));
    for (const auto& storage : account["storage"].items()) {
      Bytes key{from_hex(storage.key())};
      Bytes value{from_hex(storage.value().get<std::string>())};
      state.set_storage(address, to_bytes32(key), to_bytes32(value));
    }
  }

  state.finalize_transaction();
  return state;
}

bool run_block(const nlohmann::json& b, BlockChain& chain, IntraBlockState& state) {
  bool invalid{b.contains("expectException")};

  Block block;
  ByteView view{};

  try {
    Bytes rlp{from_hex(b["rlp"].get<std::string>())};
    view = rlp;
    rlp::decode(view, block);
  } catch (const std::exception& e) {
    if (invalid) {
      return true;
    }
    std::cout << e.what() << "\n";
    return false;
  }

  if (!view.empty()) {
    if (invalid) {
      return true;
    }
    std::cout << "Extra RLP input\n";
    return false;
  }

  chain.insert_block(block);

  for (Transaction& txn : block.transactions) {
    txn.recover_sender();
  }

  ExecutionProcessor processor{chain, block, state};
  try {
    processor.execute_block();
  } catch (const ValidationError& e) {
    if (invalid) {
      return true;
    }
    std::cout << e.what() << "\n";
    return false;
  }

  if (invalid) {
    std::cout << "Invalid block executed successfully\n";
    std::cout << "Expected: " << b["expectException"] << "\n";
  }
  return !invalid;
}

bool check_post(const IntraBlockState& state, const nlohmann::json& expected) {
  for (const auto& entry : expected.items()) {
    evmc::address address{to_address(from_hex(entry.key()))};
    const nlohmann::json& account{entry.value()};

    Bytes expected_balance{from_hex(account["balance"].get<std::string>())};
    intx::uint256 actual_balance{state.get_balance(address)};
    if (actual_balance != rlp::read_uint256(expected_balance, /*allow_leading_zeros=*/true)) {
      std::cout << "Balance mismatch for " << entry.key() << ":\n";
      std::cout << to_string(actual_balance, 16) << " ≠ " << account["balance"] << "\n";
      return false;
    }

    Bytes nonce_str{from_hex(account["nonce"].get<std::string>())};
    uint64_t expected_nonce{rlp::read_uint64(nonce_str, /*allow_leading_zeros=*/true)};
    uint64_t actual_nonce{state.get_nonce(address)};
    if (actual_nonce != expected_nonce) {
      std::cout << "Nonce mismatch for " << entry.key() << ":\n";
      std::cout << actual_nonce << " ≠ " << expected_nonce << "\n";
      return false;
    }

    auto expected_code{account["code"].get<std::string>()};
    Bytes actual_code{state.get_code(address)};
    if (actual_code != from_hex(expected_code)) {
      std::cout << "Code mismatch for " << entry.key() << ":\n";
      std::cout << to_hex(actual_code) << " ≠ " << expected_code << "\n";
      return false;
    }

    for (const auto& storage : account["storage"].items()) {
      Bytes key{from_hex(storage.key())};
      Bytes expected_value{from_hex(storage.value().get<std::string>())};
      evmc::bytes32 actual_value{state.get_current_storage(address, to_bytes32(key))};
      if (actual_value != to_bytes32(expected_value)) {
        std::cout << "Storage mismatch for " << entry.key() << " at " << storage.key() << ":\n";
        std::cout << to_hex(actual_value) << " ≠ " << to_hex(expected_value) << "\n";
        return false;
      }
    }
  }

  return true;
}

bool run_blockchain_test(const nlohmann::json& j) {
  Bytes genesis_rlp{from_hex(j["genesisRLP"].get<std::string>())};
  ByteView genesis_view{genesis_rlp};
  Block genesis_block;
  rlp::decode(genesis_view, genesis_block);

  BlockChain chain{nullptr};
  std::string network{j["network"].get<std::string>()};
  chain.config = kNetworkConfig.at(network);
  chain.insert_block(genesis_block);

  IntraBlockState state{pre_state(j["pre"])};

  for (const auto& b : j["blocks"]) {
    if (!run_block(b, chain, state)) {
      return false;
    }
  }

  return check_post(state, j["postState"]);
}

struct RunResult {
  size_t passed{0};
  size_t failed{0};
  size_t skipped{0};
};

RunResult run_blockchain_file(const fs::path& file_path) {
  std::ifstream in{file_path};
  nlohmann::json json;
  in >> json;

  RunResult res{};

  for (const auto& test : json.items()) {
    if (!test.value().contains("postState")) {
      std::cout << "postStateHash is not supported\n";
      std::cout << test.key() << " ";
      for (size_t i{test.key().length() + 1}; i < kColumnWidth; ++i) {
        std::cout << '.';
      }
      std::cout << " Skipped\n";

      ++res.skipped;
      continue;
    }

    if (run_blockchain_test(test.value())) {
      ++res.passed;
    } else {
      ++res.failed;
      std::cout << test.key() << " ";
      for (size_t i{test.key().length() + 1}; i < kColumnWidth; ++i) {
        std::cout << '.';
      }
      std::cout << "\033[1;31m  Failed\033[0m\n";
    }
  }

  return res;
}

int main() {
  size_t passed{0};
  size_t failed{0};
  size_t skipped{0};

  for (auto i = fs::recursive_directory_iterator(kBlockchainDir);
       i != fs::recursive_directory_iterator{}; ++i) {
    if (kSlowTests.count(*i) || kFailingTests.count(*i)) {
      i.disable_recursion_pending();
    } else if (i->is_regular_file()) {
      RunResult res{run_blockchain_file(*i)};
      passed += res.passed;
      failed += res.failed;
      skipped += res.skipped;
    }
  }

  std::cout << "\033[0;32m" << passed << " tests passed\033[0m, ";
  if (failed) {
    std::cout << "\033[1;31m";
  }
  std::cout << failed << " failed";
  if (failed) {
    std::cout << "\033[0m";
  }
  std::cout << ", " << skipped << " skipped\n";

  return failed;
}
