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

#include <boost/filesystem.hpp>
#include <exception>
#include <fstream>
#include <iostream>
#include <map>
#include <nlohmann/json.hpp>
#include <set>
#include <silkworm/chain/blockchain.hpp>
#include <silkworm/chain/difficulty.hpp>
#include <silkworm/common/util.hpp>
#include <silkworm/execution/processor.hpp>
#include <silkworm/rlp/decode.hpp>
#include <silkworm/state/intra_block_state.hpp>
#include <silkworm/state/memory_buffer.hpp>
#include <silkworm/types/block.hpp>
#include <string>
#include <string_view>

// See https://ethereum-tests.readthedocs.io

using namespace silkworm;

namespace fs = boost::filesystem;

static const fs::path kRootDir{SILKWORM_CONSENSUS_TEST_DIR};

static const fs::path kDifficultyDir{kRootDir / "BasicTests"};

static const fs::path kBlockchainDir{kRootDir / "BlockchainTests"};

static const fs::path kTransactionDir{kRootDir / "TransactionTests"};

static const std::set<fs::path> kExcludedTests{
    kBlockchainDir / "GeneralStateTests" / "stTimeConsuming",

    // Nonce >= 2^64 is not supported.
    // Geth excludes this test as well:
    // https://github.com/ethereum/go-ethereum/blob/v1.9.25/tests/transaction_test.go#L40
    kTransactionDir / "ttNonce" / "TransactionWithHighNonce256.json",

    // Gas limit >= 2^64 is not supported; see EIP-1985.
    // Geth excludes this test as well:
    // https://github.com/ethereum/go-ethereum/blob/v1.9.25/tests/transaction_test.go#L31
    kTransactionDir / "ttGasLimit" / "TransactionWithGasLimitxPriceOverflow.json",
};

constexpr size_t kColumnWidth{80};

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
         {},  // berlin_block
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
    {"EIP2384",
     {
         1,  // chain_id
         0,  // homestead_block
         0,  // tangerine_whistle_block
         0,  // spurious_dragon_block
         0,  // byzantium_block
         0,  // constantinople_block
         0,  // petersburg_block
         0,  // istanbul_block
         0,  // muir_glacier_block
     }},
};

static const std::map<std::string, silkworm::ChainConfig> kDifficultyConfig{
    {"difficulty.json", kMainnetConfig},
    {"difficultyByzantium.json", kNetworkConfig.at("Byzantium")},
    {"difficultyConstantinople.json", kNetworkConfig.at("Constantinople")},
    {"difficultyCustomMainNetwork.json", kMainnetConfig},
    {"difficultyEIP2384_random_to20M.json", kNetworkConfig.at("EIP2384")},
    {"difficultyEIP2384_random.json", kNetworkConfig.at("EIP2384")},
    {"difficultyEIP2384.json", kNetworkConfig.at("EIP2384")},
    {"difficultyFrontier.json", kNetworkConfig.at("Frontier")},
    {"difficultyHomestead.json", kNetworkConfig.at("Homestead")},
    {"difficultyMainNetwork.json", kMainnetConfig},
    {"difficultyRopsten.json", kRopstenConfig},
};

static void check_rlp_err(rlp::DecodingResult err) {
    if (err != rlp::DecodingResult::kOk) {
        throw err;
    }
}

// https://ethereum-tests.readthedocs.io/en/latest/test_types/blockchain_tests.html#pre-prestate-section
void init_pre_state(const nlohmann::json& pre, StateBuffer& state) {
    for (const auto& entry : pre.items()) {
        evmc::address address{to_address(from_hex(entry.key()).value())};
        const nlohmann::json& j{entry.value()};

        Account account;
        Bytes balance_str{from_hex(j["balance"].get<std::string>()).value()};
        auto [balance, err1]{rlp::read_uint256(balance_str, /*allow_leading_zeros=*/true)};
        check_rlp_err(err1);
        account.balance = balance;
        Bytes nonce_str{from_hex(j["nonce"].get<std::string>()).value()};
        auto [nonce, err2]{rlp::read_uint64(nonce_str, /*allow_leading_zeros=*/true)};
        check_rlp_err(err2);
        account.nonce = nonce;

        Bytes code{from_hex(j["code"].get<std::string>()).value()};
        if (!code.empty()) {
            account.incarnation = 1;
            ethash::hash256 hash{keccak256(code)};
            std::memcpy(account.code_hash.bytes, hash.bytes, kHashLength);
            state.update_account_code(address, account.incarnation, account.code_hash, code);
        }

        state.update_account(address, /*initial=*/std::nullopt, account);

        for (const auto& storage : j["storage"].items()) {
            Bytes key{from_hex(storage.key()).value()};
            Bytes value{from_hex(storage.value().get<std::string>()).value()};
            state.update_storage(address, account.incarnation, to_bytes32(key), /*initial=*/{}, to_bytes32(value));
        }
    }
}

enum Status { kPassed, kFailed, kSkipped };

Status run_block(const nlohmann::json& json_block, Blockchain& blockchain) {
    bool invalid{json_block.contains("expectException")};

    std::optional<Bytes> rlp{from_hex(json_block["rlp"].get<std::string>())};
    if (!rlp) {
        if (invalid) {
            return kPassed;
        }
        std::cout << "Failure to read hex\n";
        return kFailed;
    }

    Block block;
    ByteView view{*rlp};
    if (rlp::decode(view, block) != rlp::DecodingResult::kOk || !view.empty()) {
        if (invalid) {
            return kPassed;
        }
        std::cout << "Failure to decode RLP\n";
        return kFailed;
    }

    bool check_state_root{invalid && json_block["expectException"].get<std::string>() == "InvalidStateRoot"};

    if (ValidationResult err{blockchain.insert_block(block, check_state_root)}; err != ValidationResult::kOk) {
        if (invalid) {
            return kPassed;
        }
        std::cout << "Validation error " << static_cast<int>(err) << "\n";
        return kFailed;
    }

    if (invalid) {
        std::cout << "Invalid block executed successfully\n";
        std::cout << "Expected: " << json_block["expectException"] << "\n";
        return kFailed;
    }

    return kPassed;
}

bool post_check(const MemoryBuffer& state, const nlohmann::json& expected) {
    if (state.number_of_accounts() != expected.size()) {
        std::cout << "Account number mismatch: " << state.number_of_accounts() << " != " << expected.size() << "\n";
        return false;
    }

    for (const auto& entry : expected.items()) {
        evmc::address address{to_address(from_hex(entry.key()).value())};
        const nlohmann::json& j{entry.value()};

        std::optional<Account> account{state.read_account(address)};
        if (!account) {
            std::cout << "Missing account " << entry.key() << "\n";
            return false;
        }

        Bytes balance_str{from_hex(j["balance"].get<std::string>()).value()};
        auto [expected_balance, err1]{rlp::read_uint256(balance_str, /*allow_leading_zeros=*/true)};
        check_rlp_err(err1);
        if (account->balance != expected_balance) {
            std::cout << "Balance mismatch for " << entry.key() << ":\n";
            std::cout << to_string(account->balance, 16) << " != " << j["balance"] << "\n";
            return false;
        }

        Bytes nonce_str{from_hex(j["nonce"].get<std::string>()).value()};
        auto [expected_nonce, err2]{rlp::read_uint64(nonce_str, /*allow_leading_zeros=*/true)};
        check_rlp_err(err2);
        if (account->nonce != expected_nonce) {
            std::cout << "Nonce mismatch for " << entry.key() << ":\n";
            std::cout << account->nonce << " != " << expected_nonce << "\n";
            return false;
        }

        auto expected_code{j["code"].get<std::string>()};
        Bytes actual_code{state.read_code(account->code_hash)};
        if (actual_code != from_hex(expected_code)) {
            std::cout << "Code mismatch for " << entry.key() << ":\n";
            std::cout << to_hex(actual_code) << " != " << expected_code << "\n";
            return false;
        }

        size_t storage_size{state.storage_size(address, account->incarnation)};
        if (storage_size != j["storage"].size()) {
            std::cout << "Storage size mismatch for " << entry.key() << ":\n";
            std::cout << storage_size << " != " << j["storage"].size() << "\n";
            return false;
        }

        for (const auto& storage : j["storage"].items()) {
            Bytes key{from_hex(storage.key()).value()};
            Bytes expected_value{from_hex(storage.value().get<std::string>()).value()};
            evmc::bytes32 actual_value{state.read_storage(address, account->incarnation, to_bytes32(key))};
            if (actual_value != to_bytes32(expected_value)) {
                std::cout << "Storage mismatch for " << entry.key() << " at " << storage.key() << ":\n";
                std::cout << to_hex(actual_value) << " != " << to_hex(expected_value) << "\n";
                return false;
            }
        }
    }

    return true;
}

// https://ethereum-tests.readthedocs.io/en/latest/test_types/blockchain_tests.html
Status blockchain_test(const nlohmann::json& json_test, std::optional<ChainConfig>) {
    std::string seal_engine{json_test["sealEngine"].get<std::string>()};
    if (seal_engine != "NoProof") {
        // TODO[Issue 144] Support Ethash sealEngine
        std::cout << seal_engine << " seal engine is not supported yet\n";
        return kSkipped;
    }

    Bytes genesis_rlp{from_hex(json_test["genesisRLP"].get<std::string>()).value()};
    ByteView genesis_view{genesis_rlp};
    Block genesis_block;
    check_rlp_err(rlp::decode(genesis_view, genesis_block));

    MemoryBuffer state;
    std::string network{json_test["network"].get<std::string>()};
    const ChainConfig& config{kNetworkConfig.at(network)};
    init_pre_state(json_test["pre"], state);

    Blockchain blockchain{state, config, genesis_block};

    for (const auto& json_block : json_test["blocks"]) {
        Status status{run_block(json_block, blockchain)};
        if (status != kPassed) {
            return status;
        }
    }

    if (json_test.contains("postStateHash")) {
        evmc::bytes32 state_root{state.state_root_hash()};
        std::string expected_hex{json_test["postStateHash"].get<std::string>()};
        if (state_root != to_bytes32(from_hex(expected_hex).value())) {
            std::cout << "postStateHash mismatch:\n";
            std::cout << to_hex(state_root) << " != " << expected_hex << "\n";
            return kFailed;
        } else {
            return kPassed;
        }
    }

    if (post_check(state, json_test["postState"])) {
        return kPassed;
    } else {
        return kFailed;
    }
}

static void print_test_status(std::string_view key, Status status) {
    std::cout << key << " ";
    for (size_t i{key.length() + 1}; i < kColumnWidth; ++i) {
        std::cout << '.';
    }
    switch (status) {
        case kPassed:
            std::cout << "\033[0;32m  Passed\033[0m\n";
            break;
        case kFailed:
            std::cout << "\033[1;31m  Failed\033[0m\n";
            break;
        case kSkipped:
            std::cout << " Skipped\n";
            break;
    }
}

struct [[nodiscard]] RunResults {
    size_t passed{0};
    size_t failed{0};
    size_t skipped{0};

    RunResults& operator+=(const RunResults& rhs) {
        passed += rhs.passed;
        failed += rhs.failed;
        skipped += rhs.skipped;
        return *this;
    }

    void add(Status status) {
        switch (status) {
            case kPassed:
                ++passed;
                break;
            case kFailed:
                ++failed;
                break;
            case kSkipped:
                ++skipped;
                break;
        }
    }
};

RunResults run_test_file(const fs::path& file_path, Status (*runner)(const nlohmann::json&, std::optional<ChainConfig>),
                         std::optional<ChainConfig> config = {}) {
    std::ifstream in{file_path.string()};
    nlohmann::json json;
    in >> json;

    RunResults res{};

    for (const auto& test : json.items()) {
        Status status{runner(test.value(), config)};
        res.add(status);
        if (status != kPassed) {
            print_test_status(test.key(), status);
        }
    }

    return res;
}

// https://ethereum-tests.readthedocs.io/en/latest/test_types/transaction_tests.html
Status transaction_test(const nlohmann::json& j, std::optional<ChainConfig>) {
    Transaction txn;
    bool decoded{false};

    std::optional<Bytes> rlp{from_hex(j["rlp"].get<std::string>())};
    if (rlp) {
        ByteView view{*rlp};
        if (rlp::decode(view, txn) == rlp::DecodingResult::kOk) {
            decoded = view.empty();
        }
    }

    for (const auto& entry : j.items()) {
        if (entry.key() == "rlp" || entry.key() == "_info") {
            continue;
        }

        bool valid{entry.value().contains("sender")};

        if (!decoded) {
            if (valid) {
                std::cout << "Failed to decode valid transaction\n";
                return kFailed;
            } else {
                continue;
            }
        }

        ChainConfig config{kNetworkConfig.at(entry.key())};
        bool homestead{config.has_homestead(0)};
        bool spurious_dragon{config.has_spurious_dragon(0)};
        bool istanbul{config.has_istanbul(0)};

        intx::uint128 g0{intrinsic_gas(txn, homestead, istanbul)};
        if (g0 > txn.gas_limit) {
            if (valid) {
                std::cout << "g0 > gas_limit for valid transaction\n";
                return kFailed;
            } else {
                continue;
            }
        }

        if (spurious_dragon) {
            txn.recover_sender(homestead, config.chain_id);
        } else {
            txn.recover_sender(homestead, {});
        }

        if (valid && !txn.from.has_value()) {
            std::cout << "Failed to recover sender\n";
            return kFailed;
        }

        if (!valid && txn.from.has_value()) {
            std::cout << entry.key() << "\n";
            std::cout << "Sender recovered for invalid transaction\n";
            return kFailed;
        }

        if (!valid) {
            continue;
        }

        std::string expected{entry.value()["sender"].get<std::string>()};
        if (to_hex(*txn.from) != expected) {
            std::cout << "Sender mismatch for " << entry.key() << ":\n";
            std::cout << to_hex(*txn.from) << " != " << expected << "\n";
            return kFailed;
        }
    }

    return kPassed;
}

// https://ethereum-tests.readthedocs.io/en/latest/test_types/difficulty_tests.html
Status difficulty_test(const nlohmann::json& j, std::optional<ChainConfig> config) {
    auto parent_timestamp{std::stoll(j["parentTimestamp"].get<std::string>(), 0, 0)};
    auto parent_difficulty{intx::from_string<intx::uint256>(j["parentDifficulty"].get<std::string>())};
    auto current_timestamp{std::stoll(j["currentTimestamp"].get<std::string>(), 0, 0)};
    auto block_number{std::stoll(j["currentBlockNumber"].get<std::string>(), 0, 0)};
    auto current_difficulty{intx::from_string<intx::uint256>(j["currentDifficulty"].get<std::string>())};

    bool parent_has_uncles{false};
    if (j.contains("parentUncles")) {
        auto parent_uncles{j["parentUncles"].get<std::string>()};
        parent_has_uncles = from_hex(parent_uncles).value() != full_view(kEmptyListHash);
    }

    intx::uint256 calculated_difficulty{canonical_difficulty(block_number, current_timestamp, parent_difficulty,
                                                             parent_timestamp, parent_has_uncles, *config)};
    if (calculated_difficulty == current_difficulty) {
        return kPassed;
    } else {
        std::cout << "Difficulty mismatch for block " << block_number << "\n";
        std::cout << hex(calculated_difficulty) << " != " << hex(current_difficulty) << "\n";
        return kFailed;
    }
}

int main() {
    RunResults res{};

    for (const auto& entry : kDifficultyConfig) {
        res += run_test_file(kDifficultyDir / entry.first, difficulty_test, entry.second);
    }

    for (auto i = fs::recursive_directory_iterator(kBlockchainDir); i != fs::recursive_directory_iterator{}; ++i) {
        if (kExcludedTests.count(*i)) {
            i.disable_recursion_pending();
        } else if (fs::is_regular_file(i->path())) {
            res += run_test_file(*i, blockchain_test);
        }
    }

    for (auto i = fs::recursive_directory_iterator(kTransactionDir); i != fs::recursive_directory_iterator{}; ++i) {
        if (kExcludedTests.count(*i)) {
            i.disable_recursion_pending();
        } else if (fs::is_regular_file(i->path())) {
            res += run_test_file(*i, transaction_test);
        }
    }

    std::cout << "\033[0;32m" << res.passed << " tests passed\033[0m, ";
    if (res.failed) {
        std::cout << "\033[1;31m";
    }
    std::cout << res.failed << " failed";
    if (res.failed) {
        std::cout << "\033[0m";
    }
    std::cout << ", " << res.skipped << " skipped\n";

    return static_cast<int>(res.failed);
}
