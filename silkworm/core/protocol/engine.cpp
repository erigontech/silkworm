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

#include "engine.hpp"

#include "clique_engine.hpp"
#include "ethash_engine.hpp"
#include "merge_engine.hpp"
#include "no_proof_engine.hpp"

namespace silkworm::protocol {

static EnginePtr pre_merge_engine(const ChainConfig& chain_config) {
    switch (chain_config.seal_engine) {
        case SealEngineType::kEthash:
            return std::make_unique<EthashEngine>(chain_config);
        case SealEngineType::kNoProof:
            return std::make_unique<NoProofEngine>(chain_config);
        case SealEngineType::kClique:
            return std::make_unique<CliqueEngine>(chain_config);
        default:
            return nullptr;
    }
}

EnginePtr engine_factory(const ChainConfig& chain_config) {
    EnginePtr engine{pre_merge_engine(chain_config)};
    if (!engine) {
        return nullptr;
    }

    if (chain_config.terminal_total_difficulty.has_value()) {
        engine = std::make_unique<MergeEngine>(std::move(engine), chain_config);
    }

    return engine;
}

}  // namespace silkworm::protocol
