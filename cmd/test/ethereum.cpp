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

#include <algorithm>
#include <atomic>
#include <filesystem>
#include <iostream>
#include <map>
#include <string>
#include <string_view>
#include <vector>

#include <CLI/CLI.hpp>
#include <evmc/loader.h>
#include <magic_enum.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/chain/genesis.hpp>
#include <silkworm/core/common/test_util.hpp>
#include <silkworm/core/protocol/blockchain.hpp>
#include <silkworm/core/protocol/ethash_rule_set.hpp>
#include <silkworm/core/protocol/intrinsic_gas.hpp>
#include <silkworm/core/state/in_memory_state.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/infra/common/stopwatch.hpp>
#include <silkworm/infra/common/terminal.hpp>
#include <silkworm/infra/concurrency/thread_pool.hpp>

// See EEST: https://github.com/erigontech/eest-fixtures.
// See legacy tests: https://ethereum-tests.readthedocs.io.

using namespace silkworm;
using namespace silkworm::protocol;

namespace fs = std::filesystem;

static const fs::path kDifficultyDir{"DifficultyTests"};

static const fs::path kBlockchainDir{"BlockchainTests"};

static const fs::path kTransactionDir{"TransactionTests"};

static const std::array kSlowTests{
    kBlockchainDir / "GeneralStateTests" / "stTimeConsuming",
    kBlockchainDir / "GeneralStateTests" / "VMTests" / "vmPerformance",
};

static const std::array kFailingTests{
    // Tests related to create address collision. Silkworm and evmone implement this scenario
    // differently:
    // Silkworm follows the older EIP-684 and clears the created account storage if not empty,
    // evmone tries to follow the newer EIP-7610 to revert the creation, however Silkworm
    // is not able to provide enough information to evmone to identify non-empty storage,
    // in the result the non-empty storage remains unchanged.
    // This scenarion don't happen in real networks. The desired behavior for implementations
    // is still being discussed.
    kBlockchainDir / "GeneralStateTests" / "stCreate2" / "create2collisionStorage.json",
    kBlockchainDir / "GeneralStateTests" / "stCreate2" / "create2collisionStorageParis.json",
    kBlockchainDir / "GeneralStateTests" / "stCreate2" / "RevertInCreateInInitCreate2.json",
    kBlockchainDir / "GeneralStateTests" / "stCreate2" / "RevertInCreateInInitCreate2Paris.json",
    kBlockchainDir / "GeneralStateTests" / "stRevertTest" / "RevertInCreateInInit.json",
    kBlockchainDir / "GeneralStateTests" / "stRevertTest" / "RevertInCreateInInit_Paris.json",
    kBlockchainDir / "GeneralStateTests" / "stSStoreTest" / "InitCollision.json",
    kBlockchainDir / "GeneralStateTests" / "stSStoreTest" / "InitCollisionParis.json",
};

static constexpr size_t kColumnWidth{80};

/// External EVMC VM.
/// It is used in potential multiple test execution threads
/// so usage may be broken if the VM is not thread-safe.
evmc_vm* exo_evm{nullptr};

enum class Status {
    kPassed,
    kFailed,
    kSkipped
};

Status run_block(const nlohmann::json& json_block, Blockchain& blockchain) {
    bool invalid{json_block.contains("expectException")};

    std::optional<Bytes> rlp{from_hex(json_block["rlp"].get<std::string>())};
    if (!rlp) {
        if (invalid) {
            return Status::kPassed;
        }
        std::cout << "Failure to read hex" << std::endl;
        return Status::kFailed;
    }

    Block block;
    ByteView view{*rlp};
    if (!rlp::decode(view, block)) {
        if (invalid) {
            return Status::kPassed;
        }
        std::cout << "Failure to decode RLP" << std::endl;
        return Status::kFailed;
    }

    const bool check_state_root{true};
    if (ValidationResult err{blockchain.insert_block(block, check_state_root)}; err != ValidationResult::kOk) {
        if (invalid) {
            return Status::kPassed;
        }
        std::cout << "Validation error " << magic_enum::enum_name<ValidationResult>(err) << std::endl;
        return Status::kFailed;
    }

    if (invalid) {
        std::cout << "Invalid block executed successfully\n";
        std::cout << "Expected: " << json_block["expectException"] << std::endl;
        return Status::kFailed;
    }

    return Status::kPassed;
}

bool post_check(const InMemoryState& state, const nlohmann::json& expected) {
    if (state.accounts().size() != expected.size()) {
        std::cout << "Account number mismatch: " << state.accounts().size() << " != " << expected.size()
                  << std::endl;

        // Find and report accounts missing from the expected set.
        for (const auto& [addr, _] : state.accounts()) {
            if (const auto addr_hex = "0x" + hex(addr); !expected.contains(addr_hex)) {
                std::cout << "Unexpected account: " << addr_hex << std::endl;
            }
        }

        return false;
    }

    for (const auto& entry : expected.items()) {
        const evmc::address address{hex_to_address(entry.key())};
        const nlohmann::json& j{entry.value()};

        std::optional<Account> account{state.read_account(address)};
        if (!account) {
            std::cout << "Missing account " << entry.key() << std::endl;
            return false;
        }

        const auto expected_balance{intx::from_string<intx::uint256>(j["balance"].get<std::string>())};
        if (account->balance != expected_balance) {
            std::cout << "Balance mismatch for " << entry.key() << ":\n"
                      << to_string(account->balance, 16) << " != " << j["balance"] << std::endl;
            return false;
        }

        const auto expected_nonce{intx::from_string<intx::uint256>(j["nonce"].get<std::string>())};
        if (account->nonce != expected_nonce) {
            std::cout << "Nonce mismatch for " << entry.key() << ":\n"
                      << account->nonce << " != " << j["nonce"] << std::endl;
            return false;
        }

        auto expected_code{j["code"].get<std::string>()};
        Bytes actual_code{state.read_code(address, account->code_hash)};
        if (actual_code != from_hex(expected_code)) {
            std::cout << "Code mismatch for " << entry.key() << ":\n"
                      << to_hex(actual_code) << " != " << expected_code << std::endl;
            return false;
        }

        size_t storage_size{state.storage_size(address, account->incarnation)};
        if (storage_size != j["storage"].size()) {
            std::cout << "Storage size mismatch for " << entry.key() << ":\n"
                      << storage_size << " != " << j["storage"].size() << std::endl;
            return false;
        }

        for (const auto& storage : j["storage"].items()) {
            Bytes key{from_hex(storage.key()).value()};
            Bytes expected_value{from_hex(storage.value().get<std::string>()).value()};
            evmc::bytes32 actual_value{state.read_storage(address, account->incarnation, to_bytes32(key))};
            if (actual_value != to_bytes32(expected_value)) {
                std::cout << "Storage mismatch for " << entry.key() << " at " << storage.key() << ":\n"
                          << to_hex(actual_value) << " != " << to_hex(expected_value) << std::endl;
                return false;
            }
        }
    }

    return true;
}

struct [[nodiscard]] RunResults {
    size_t passed{0};
    size_t failed{0};
    size_t skipped{0};

    constexpr RunResults() = default;

    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    constexpr RunResults(Status status) {
        switch (status) {
            case Status::kPassed:
                passed = 1;
                return;
            case Status::kFailed:
                failed = 1;
                return;
            case Status::kSkipped:
                skipped = 1;
                return;
        }
    }

    RunResults& operator+=(const RunResults& rhs) {
        passed += rhs.passed;
        failed += rhs.failed;
        skipped += rhs.skipped;
        return *this;
    }
};

// https://ethereum-tests.readthedocs.io/en/latest/test_types/blockchain_tests.html
RunResults blockchain_test(const nlohmann::json& json_test) {
    const auto network{json_test["network"].get<std::string>()};
    const auto config_it{test::kNetworkConfig.find(network)};
    if (config_it == test::kNetworkConfig.end()) {
        std::cout << "unknown network " << network << std::endl;
        return Status::kSkipped;
    }

    Bytes genesis_rlp{from_hex(json_test["genesisRLP"].get<std::string>()).value()};
    ByteView genesis_view{genesis_rlp};
    Block genesis_block;
    if (!rlp::decode(genesis_view, genesis_block)) {
        std::cout << "Failure to decode genesisRLP" << std::endl;
        return Status::kFailed;
    }

    InMemoryState state{read_genesis_allocation(json_test["pre"])};
    Blockchain blockchain{state, config_it->second, genesis_block};
    blockchain.exo_evm = exo_evm;

    for (const auto& json_block : json_test["blocks"]) {
        Status status{run_block(json_block, blockchain)};
        if (status != Status::kPassed) {
            return status;
        }
    }

    if (json_test.contains("postStateHash")) {
        evmc::bytes32 state_root{state.state_root_hash()};
        std::string expected_hex{json_test["postStateHash"].get<std::string>()};
        if (state_root != to_bytes32(from_hex(expected_hex).value())) {
            std::cout << "postStateHash mismatch:\n"
                      << to_hex(state_root) << " != " << expected_hex << std::endl;
            return Status::kFailed;
        }
        return Status::kPassed;
    }

    if (post_check(state, json_test["postState"])) {
        return Status::kPassed;
    }
    return Status::kFailed;
}

static void print_test_status(std::string_view key, const RunResults& res) {
    std::cout << key << " ";
    for (size_t i{key.size() + 1}; i < kColumnWidth; ++i) {
        std::cout << '.';
    }
    if (res.failed) {
        std::cout << kColorMaroonHigh << "  Failed" << kColorReset << std::endl;
    } else if (res.skipped) {
        std::cout << " Skipped" << std::endl;
    } else {
        std::cout << kColorGreen << "  Passed" << kColorReset << std::endl;
    }
}

std::atomic<size_t> total_passed{0};
std::atomic<size_t> total_failed{0};
std::atomic<size_t> total_skipped{0};

using RunnerFunc = RunResults (*)(const nlohmann::json&);

void run_test_file(const fs::path& file_path, RunnerFunc runner, std::string_view filter) {
    std::ifstream in{file_path.string()};
    nlohmann::json json;

    try {
        in >> json;
    } catch (nlohmann::detail::parse_error& e) {
        std::cerr << e.what() << "\n";
        print_test_status(file_path.string(), Status::kSkipped);
        ++total_skipped;
        return;
    }

    RunResults total;

    for (const auto& test : json.items()) {
        if (!filter.empty() && test.key().find(filter) == std::string::npos) {
            continue;
        }
        const RunResults r = runner(test.value());
        total += r;
        if (r.failed || r.skipped) {
            print_test_status(test.key(), r);
        }
    }

    total_passed += total.passed;
    total_failed += total.failed;
    total_skipped += total.skipped;
}

// https://ethereum-tests.readthedocs.io/en/latest/test_types/transaction_tests.html
RunResults transaction_test(const nlohmann::json& j) {
    Transaction txn;
    bool decoded{false};

    std::optional<Bytes> rlp{from_hex(j["txbytes"].get<std::string>())};
    if (rlp) {
        ByteView view{*rlp};
        if (rlp::decode_transaction(view, txn, rlp::Eip2718Wrapping::kNone)) {
            decoded = view.empty();
        }
    }

    for (const auto& entry : j["result"].items()) {
        const auto& test{entry.value()};
        const bool should_be_valid{!test.contains("exception")};

        if (!decoded) {
            if (should_be_valid) {
                std::cout << "Failed to decode valid transaction" << std::endl;
                return Status::kFailed;
            }
            continue;
        }

        const ChainConfig& config{test::kNetworkConfig.at(entry.key())};
        const evmc_revision rev{config.revision(/*block_num=*/0, /*block_time=*/0)};

        if (ValidationResult err{
                pre_validate_transaction(txn, rev, config.chain_id, /*base_fee_per_gas=*/std::nullopt,
                                         /*blob_gas_price=*/std::nullopt)};
            err != ValidationResult::kOk) {
            if (should_be_valid) {
                std::cout << "Validation error " << magic_enum::enum_name<ValidationResult>(err) << std::endl;
                return Status::kFailed;
            }
            continue;
        }

        if (should_be_valid && !txn.sender()) {
            std::cout << "Failed to recover sender" << std::endl;
            return Status::kFailed;
        }

        if (!should_be_valid && txn.sender()) {
            std::cout << entry.key() << "\n"
                      << "Sender recovered for invalid transaction" << std::endl;
            return Status::kFailed;
        }

        if (!should_be_valid) {
            continue;
        }

        const std::string expected_sender{test["sender"].get<std::string>()};
        if (txn.sender() != hex_to_address(expected_sender)) {
            std::cout << "Sender mismatch for " << entry.key() << ":\n"
                      << *txn.sender() << " != " << expected_sender << std::endl;
            return Status::kFailed;
        }

        const auto expected_intrinsic_gas{intx::from_string<intx::uint256>(test["intrinsicGas"].get<std::string>())};
        const auto calculated_intrinsic_gas{intrinsic_gas(txn, rev)};
        if (calculated_intrinsic_gas != expected_intrinsic_gas) {
            std::cout << "Intrinsic gas mismatch for " << entry.key() << ":\n"
                      << intx::to_string(calculated_intrinsic_gas, /*base=*/16)
                      << " != " << intx::to_string(expected_intrinsic_gas, /*base=*/16) << std::endl;
            return Status::kFailed;
        }
    }

    return Status::kPassed;
}

// https://ethereum-tests.readthedocs.io/en/latest/test_types/difficulty_tests.html
Status individual_difficulty_test(const nlohmann::json& j, const ChainConfig& config) {
    auto parent_timestamp{std::stoull(j["parentTimestamp"].get<std::string>(), nullptr, 0)};
    auto parent_difficulty{intx::from_string<intx::uint256>(j["parentDifficulty"].get<std::string>())};
    auto current_timestamp{std::stoull(j["currentTimestamp"].get<std::string>(), nullptr, 0)};
    auto block_num{std::stoull(j["currentBlockNumber"].get<std::string>(), nullptr, 0)};
    auto current_difficulty{intx::from_string<intx::uint256>(j["currentDifficulty"].get<std::string>())};

    bool parent_has_uncles{false};
    if (j.contains("parentUncles")) {
        auto parent_uncles{j["parentUncles"].get<std::string>()};
        if (parent_uncles == "0x00") {
            parent_has_uncles = false;
        } else if (parent_uncles == "0x01") {
            parent_has_uncles = true;
        } else {
            std::cout << "Invalid parentUncles " << parent_uncles << std::endl;
            return Status::kFailed;
        }
    }

    intx::uint256 calculated_difficulty{EthashRuleSet::difficulty(block_num, current_timestamp, parent_difficulty,
                                                                  parent_timestamp, parent_has_uncles, config)};
    if (calculated_difficulty == current_difficulty) {
        return Status::kPassed;
    }
    std::cout << "Difficulty mismatch for block " << block_num << "\n"
              << hex(calculated_difficulty) << " != " << hex(current_difficulty) << std::endl;
    return Status::kFailed;
}

RunResults difficulty_tests(const nlohmann::json& outer) {
    RunResults res;

    for (const auto& network : outer.items()) {
        if (network.key() == "_info") {
            continue;
        }

        const ChainConfig& config{test::kNetworkConfig.at(network.key())};

        for (const auto& test : network.value().items()) {
            const Status status{individual_difficulty_test(test.value(), config)};
            res += status;
        }
    }

    return res;
}

bool exclude_test(const fs::path& p, const fs::path& root_dir, bool include_slow_tests) {
    const auto path_fits = [&p, &root_dir](const fs::path& e) { return root_dir / e == p; };
    return std::ranges::any_of(kFailingTests, path_fits) ||
           (!include_slow_tests && std::ranges::any_of(kSlowTests, path_fits));
}

int main(int argc, char* argv[]) {
    StopWatch sw;
    sw.start();

    CLI::App app{"Run Ethereum EL tests"};

    std::string evm_path;
    app.add_option("--evm", evm_path, "Path to EVMC-compliant VM");
    std::string tests_path{SILKWORM_ETHEREUM_TESTS_DIR};
    app.add_option("--tests", tests_path, "Path to Ethereum EL tests")
        ->capture_default_str()
        ->check(CLI::ExistingDirectory);
    std::string test_name_filter;
    app.add_option("--filter", test_name_filter, "Inclusion filter matching the test names to be executed")
        ->capture_default_str();
    unsigned num_threads{std::thread::hardware_concurrency()};
    app.add_option("--threads", num_threads, "Number of parallel threads")->capture_default_str();
    bool include_slow_tests{false};
    app.add_flag("--slow", include_slow_tests, "Run slow tests");

    CLI11_PARSE(app, argc, argv)
    init_terminal();

    if (!evm_path.empty()) {
        evmc_loader_error_code err{EVMC_LOADER_UNSPECIFIED_ERROR};
        exo_evm = evmc_load_and_configure(evm_path.c_str(), &err);
        if (err) {
            std::cerr << "Failed to load EVM: " << evmc_last_error_msg() << std::endl;
            return -1;
        }
    }

    size_t stack_size{50 * kMebi};
#ifdef NDEBUG
    stack_size = 16 * kMebi;
#endif
    ThreadPool thread_pool{num_threads, stack_size};

    const fs::path root_dir{tests_path};

    static const std::map<fs::path, RunnerFunc> kTestTypes{
        {kDifficultyDir, difficulty_tests},
        {kBlockchainDir, blockchain_test},
        {kTransactionDir, transaction_test},
    };

    for (const auto& entry : kTestTypes) {
        const fs::path& dir{root_dir / entry.first};
        const RunnerFunc runner{entry.second};

        if (!fs::exists(dir)) {
            continue;
        }

        for (auto i = fs::recursive_directory_iterator(dir); i != fs::recursive_directory_iterator{}; ++i) {
            if (exclude_test(*i, root_dir, include_slow_tests)) {
                ++total_skipped;
                i.disable_recursion_pending();
            } else if (fs::is_regular_file(i->path()) && i->path().extension() == ".json") {
                const fs::path path{*i};
                thread_pool.push_task([=]() { run_test_file(path, runner, test_name_filter); });
            }
        }
    }

    thread_pool.wait_for_tasks();

    std::cout << kColorGreen << total_passed << " tests passed" << kColorReset << ", ";
    if (total_failed != 0) {
        std::cout << kColorMaroonHigh;
    }
    std::cout << total_failed << " failed";
    if (total_failed != 0) {
        std::cout << kColorReset;
    }
    std::cout << ", " << total_skipped << " skipped";

    const auto [_, duration] = sw.lap();
    std::cout << " in " << StopWatch::format(duration) << std::endl;

    return total_failed != 0;
}
