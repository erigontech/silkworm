//
// Created by jacek on 4/17/23.
//

#include <utility>

#include <nlohmann/json.hpp>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/common/test_util.hpp>

using namespace silkworm;
using namespace silkworm::protocol;

static const std::map<std::string, ChainConfig> kNetworkConfig{
    {"Frontier", test::kFrontierConfig},
    {"Homestead",
     {
         .chain_id = 1,
         .protocol_rule_set = RuleSetType::kNoProof,
         .homestead_block = 0,
     }},
    {"FrontierToHomesteadAt5",
     {
         .chain_id = 1,
         .protocol_rule_set = RuleSetType::kNoProof,
         .homestead_block = 5,
     }},
    {"HomesteadToDaoAt5",
     {
         .chain_id = 1,
         .protocol_rule_set = RuleSetType::kNoProof,
         .homestead_block = 0,
         .dao_block = 5,
     }},
    {"EIP150",
     {
         .chain_id = 1,
         .protocol_rule_set = RuleSetType::kNoProof,
         .homestead_block = 0,
         .tangerine_whistle_block = 0,
     }},
    {"HomesteadToEIP150At5",
     {
         .chain_id = 1,
         .protocol_rule_set = RuleSetType::kNoProof,
         .homestead_block = 0,
         .tangerine_whistle_block = 5,
     }},
    {"EIP158",
     {
         .chain_id = 1,
         .protocol_rule_set = RuleSetType::kNoProof,
         .homestead_block = 0,
         .tangerine_whistle_block = 0,
         .spurious_dragon_block = 0,
     }},
    {"Byzantium",
     {
         .chain_id = 1,
         .protocol_rule_set = RuleSetType::kNoProof,
         .homestead_block = 0,
         .tangerine_whistle_block = 0,
         .spurious_dragon_block = 0,
         .byzantium_block = 0,
     }},
    {"EIP158ToByzantiumAt5",
     {
         .chain_id = 1,
         .protocol_rule_set = RuleSetType::kNoProof,
         .homestead_block = 0,
         .tangerine_whistle_block = 0,
         .spurious_dragon_block = 0,
         .byzantium_block = 5,
     }},
    {"Constantinople",
     {
         .chain_id = 1,
         .protocol_rule_set = RuleSetType::kNoProof,
         .homestead_block = 0,
         .tangerine_whistle_block = 0,
         .spurious_dragon_block = 0,
         .byzantium_block = 0,
         .constantinople_block = 0,
     }},
    {"ConstantinopleFix",
     {
         .chain_id = 1,
         .protocol_rule_set = RuleSetType::kNoProof,
         .homestead_block = 0,
         .tangerine_whistle_block = 0,
         .spurious_dragon_block = 0,
         .byzantium_block = 0,
         .constantinople_block = 0,
         .petersburg_block = 0,
     }},
    {"ByzantiumToConstantinopleFixAt5",
     {
         .chain_id = 1,
         .protocol_rule_set = RuleSetType::kNoProof,
         .homestead_block = 0,
         .tangerine_whistle_block = 0,
         .spurious_dragon_block = 0,
         .byzantium_block = 0,
         .constantinople_block = 5,
         .petersburg_block = 5,
     }},
    {"Istanbul",
     {
         .chain_id = 1,
         .protocol_rule_set = RuleSetType::kNoProof,
         .homestead_block = 0,
         .tangerine_whistle_block = 0,
         .spurious_dragon_block = 0,
         .byzantium_block = 0,
         .constantinople_block = 0,
         .petersburg_block = 0,
         .istanbul_block = 0,
     }},
    {"EIP2384",
     {
         .chain_id = 1,
         .protocol_rule_set = RuleSetType::kNoProof,
         .homestead_block = 0,
         .tangerine_whistle_block = 0,
         .spurious_dragon_block = 0,
         .byzantium_block = 0,
         .constantinople_block = 0,
         .petersburg_block = 0,
         .istanbul_block = 0,
         .muir_glacier_block = 0,
     }},
    {"Berlin",
     {
         .chain_id = 1,
         .protocol_rule_set = RuleSetType::kNoProof,
         .homestead_block = 0,
         .tangerine_whistle_block = 0,
         .spurious_dragon_block = 0,
         .byzantium_block = 0,
         .constantinople_block = 0,
         .petersburg_block = 0,
         .istanbul_block = 0,
         .muir_glacier_block = 0,
         .berlin_block = 0,
     }},
    {"London", test::kLondonConfig},
    {"BerlinToLondonAt5",
     {
         .chain_id = 1,
         .protocol_rule_set = RuleSetType::kNoProof,
         .homestead_block = 0,
         .tangerine_whistle_block = 0,
         .spurious_dragon_block = 0,
         .byzantium_block = 0,
         .constantinople_block = 0,
         .petersburg_block = 0,
         .istanbul_block = 0,
         .muir_glacier_block = 0,
         .berlin_block = 0,
         .london_block = 5,
     }},
    {"ArrowGlacier",
     {
         .chain_id = 1,
         .protocol_rule_set = RuleSetType::kNoProof,
         .homestead_block = 0,
         .tangerine_whistle_block = 0,
         .spurious_dragon_block = 0,
         .byzantium_block = 0,
         .constantinople_block = 0,
         .petersburg_block = 0,
         .istanbul_block = 0,
         .berlin_block = 0,
         .london_block = 0,
         .arrow_glacier_block = 0,
     }},
    {"GrayGlacier",
     {
         .chain_id = 1,
         .protocol_rule_set = RuleSetType::kNoProof,
         .homestead_block = 0,
         .tangerine_whistle_block = 0,
         .spurious_dragon_block = 0,
         .byzantium_block = 0,
         .constantinople_block = 0,
         .petersburg_block = 0,
         .istanbul_block = 0,
         .berlin_block = 0,
         .london_block = 0,
         .gray_glacier_block = 0,
     }},
    {"Merge",
     {
         .chain_id = 1,
         .protocol_rule_set = RuleSetType::kNoProof,
         .homestead_block = 0,
         .tangerine_whistle_block = 0,
         .spurious_dragon_block = 0,
         .byzantium_block = 0,
         .constantinople_block = 0,
         .petersburg_block = 0,
         .istanbul_block = 0,
         .berlin_block = 0,
         .london_block = 0,
         .terminal_total_difficulty = 0,
     }},
    {"ArrowGlacierToMergeAtDiffC0000",
     {
         .chain_id = 1,
         .protocol_rule_set = RuleSetType::kNoProof,
         .homestead_block = 0,
         .tangerine_whistle_block = 0,
         .spurious_dragon_block = 0,
         .byzantium_block = 0,
         .constantinople_block = 0,
         .petersburg_block = 0,
         .istanbul_block = 0,
         .berlin_block = 0,
         .london_block = 0,
         .arrow_glacier_block = 0,
         .terminal_total_difficulty = 0xC0000,
     }},
    {"Shanghai", test::kShanghaiConfig},
    {"MergeToShanghaiAtTime15k",
     {
         .chain_id = 1,
         .protocol_rule_set = RuleSetType::kNoProof,
         .homestead_block = 0,
         .tangerine_whistle_block = 0,
         .spurious_dragon_block = 0,
         .byzantium_block = 0,
         .constantinople_block = 0,
         .petersburg_block = 0,
         .istanbul_block = 0,
         .berlin_block = 0,
         .london_block = 0,
         .terminal_total_difficulty = 0,
         .shanghai_time = 15'000,
     }},
};

class ExpectedSubState {
  public:
    unsigned index{};
    evmc::bytes32 stateHash;
    evmc::bytes32 logsHash;
    unsigned long dataIndex{};
    unsigned long gasIndex{};
    unsigned long valueIndex{};

    void print_summary(const std::string& result) {
        std::cout << "[Expected State Index] Data: " << dataIndex << ", Gas: " << gasIndex << ", Value" << valueIndex << " [Result]" << result << std::endl;
    }
};

class ExpectedState {
    nlohmann::json stateData;

  public:
    std::string forkName;
    explicit ExpectedState(const nlohmann::json& data, const std::string& name) noexcept {
        stateData = data;
        forkName = name;
    }

    silkworm::ChainConfig getConfig() {
        const auto config_it{kNetworkConfig.find(forkName)};
        if (config_it == kNetworkConfig.end()) {
            std::cout << "unknown network " << forkName << std::endl;
            throw std::invalid_argument(forkName);
        }
        const ChainConfig& config{config_it->second};
        return config;
    }

    std::vector<ExpectedSubState> getSubStates() {
        std::vector<ExpectedSubState> subStates;
        unsigned i = 0;

        for (auto& tx : stateData) {
            ExpectedSubState subState;

            subState.stateHash = silkworm::to_bytes32(from_hex(tx["hash"].get<std::string>()).value_or(Bytes{}));
            subState.logsHash = silkworm::to_bytes32(from_hex(tx["logs"].get<std::string>()).value_or(Bytes{}));
            subState.dataIndex = tx["indexes"]["data"].get<unsigned long>();
            subState.gasIndex = tx["indexes"]["gas"].get<unsigned long>();
            subState.valueIndex = tx["indexes"]["value"].get<unsigned long>();
            subStates.push_back(subState);
            ++i;
        }

        return subStates;
    }
};
