//
// Created by jacek on 4/17/23.
//

#include <utility>

#include <nlohmann/json.hpp>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/common/test_util.hpp>

using namespace silkworm;

static const std::map<std::string, silkworm::ChainConfig> kNetworkConfig{
    {"Frontier", test::kFrontierConfig},
    {"Homestead",
     {
         .chain_id = 1,
         .seal_engine = SealEngineType::kNoProof,
         .homestead_block = 0,
     }},
    {"FrontierToHomesteadAt5",
     {
         .chain_id = 1,
         .seal_engine = SealEngineType::kNoProof,
         .homestead_block = 5,
     }},
    {"HomesteadToDaoAt5",
     {
         .chain_id = 1,
         .seal_engine = SealEngineType::kNoProof,
         .homestead_block = 0,
         .dao_block = 5,
     }},
    {"EIP150",
     {
         .chain_id = 1,
         .seal_engine = SealEngineType::kNoProof,
         .homestead_block = 0,
         .tangerine_whistle_block = 0,
     }},
    {"HomesteadToEIP150At5",
     {
         .chain_id = 1,
         .seal_engine = SealEngineType::kNoProof,
         .homestead_block = 0,
         .tangerine_whistle_block = 5,
     }},
    {"EIP158",
     {
         .chain_id = 1,
         .seal_engine = SealEngineType::kNoProof,
         .homestead_block = 0,
         .tangerine_whistle_block = 0,
         .spurious_dragon_block = 0,
     }},
    {"Byzantium",
     {
         .chain_id = 1,
         .seal_engine = SealEngineType::kNoProof,
         .homestead_block = 0,
         .tangerine_whistle_block = 0,
         .spurious_dragon_block = 0,
         .byzantium_block = 0,
     }},
    {"EIP158ToByzantiumAt5",
     {
         .chain_id = 1,
         .seal_engine = SealEngineType::kNoProof,
         .homestead_block = 0,
         .tangerine_whistle_block = 0,
         .spurious_dragon_block = 0,
         .byzantium_block = 5,
     }},
    {"Constantinople",
     {
         .chain_id = 1,
         .seal_engine = SealEngineType::kNoProof,
         .homestead_block = 0,
         .tangerine_whistle_block = 0,
         .spurious_dragon_block = 0,
         .byzantium_block = 0,
         .constantinople_block = 0,
     }},
    {"ConstantinopleFix",
     {
         .chain_id = 1,
         .seal_engine = SealEngineType::kNoProof,
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
         .seal_engine = SealEngineType::kNoProof,
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
         .seal_engine = SealEngineType::kNoProof,
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
         .seal_engine = SealEngineType::kNoProof,
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
         .seal_engine = SealEngineType::kNoProof,
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
         .seal_engine = SealEngineType::kNoProof,
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
         .seal_engine = SealEngineType::kNoProof,
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
         .seal_engine = SealEngineType::kNoProof,
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
         .seal_engine = SealEngineType::kNoProof,
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
         .seal_engine = SealEngineType::kNoProof,
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
         .seal_engine = SealEngineType::kNoProof,
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

class ExpectedStateTransaction {
public:
    evmc::bytes32 txHash;
    evmc::bytes32 logsHash;
    unsigned long dataIndex{};
    unsigned long gasIndex{};
    unsigned long valueIndex{};
};

class ExpectedState {
    nlohmann::json stateData;
    std::string forkName;

  public:
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

    std::unique_ptr<consensus::IEngine> getEngine() {
        auto chain_config{getConfig()};

        auto engine{consensus::engine_factory(chain_config)};

        if (!engine) {
            throw std::runtime_error("Unable to retrieve consensus engine");
        }

        return engine;
    }

    std::vector<ExpectedStateTransaction> getTransactions() {
        std::vector<ExpectedStateTransaction> transactions;

        for (auto& tx : stateData) {
            ExpectedStateTransaction transaction;

            transaction.txHash = silkworm::to_bytes32(from_hex(tx["hash"].get<std::string>()).value_or(Bytes{}));
            transaction.logsHash = silkworm::to_bytes32(from_hex(tx["logs"].get<std::string>()).value_or(Bytes{}));
            transaction.dataIndex = tx["indexes"]["data"].get<unsigned long>();
            transaction.gasIndex = tx["indexes"]["gas"].get<unsigned long>();
            transaction.valueIndex = tx["indexes"]["value"].get<unsigned long>();
            transactions.push_back(transaction);
        }

        return transactions;
    }    
};
