/*
   Copyright 2021 The Silkworm Authors

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

#include "config.hpp"

namespace silkworm {

nlohmann::json ChainConfig::Json() const noexcept {
    nlohmann::json ret;

    ret["chainId"] = chain_id;

#define OPTIONAL_TO_JSON(SOURCE, TARGET) \
    if (SOURCE.has_value()) {            \
        ret[TARGET] = SOURCE.value();    \
    }

    OPTIONAL_TO_JSON(homestead_block, "homesteadBlock");
    OPTIONAL_TO_JSON(tangerine_whistle_block, "eip150Block");
    OPTIONAL_TO_JSON(spurious_dragon_block, "eip155Block");
    OPTIONAL_TO_JSON(byzantium_block, "byzantiumBlock");
    OPTIONAL_TO_JSON(constantinople_block, "constantinopleBlock");
    OPTIONAL_TO_JSON(petersburg_block, "petersburgBlock");
    OPTIONAL_TO_JSON(istanbul_block, "istanbulBlock");
    OPTIONAL_TO_JSON(muir_glacier_block, "muirGlacierBlock");
    OPTIONAL_TO_JSON(dao_block, "daoForkBlock");
    OPTIONAL_TO_JSON(berlin_block, "berlinBlock");

#undef OPTIONAL_TO_JSON

    return ret;
}

bool operator==(const ChainConfig& a, const ChainConfig& b) {
    return a.Json() == b.Json();
}
std::ostream& operator<<(std::ostream& out, const ChainConfig& obj) { return out << obj.Json().dump(); }

}  // namespace silkworm
