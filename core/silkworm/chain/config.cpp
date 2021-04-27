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

static inline void member_to_json(nlohmann::json& json, const std::string& key,
                                  const std::optional<uint64_t>& source) {
    if (source.has_value()) {
        json[key] = source.value();
    }
}

nlohmann::json ChainConfig::Json() const noexcept {
    nlohmann::json ret;

    ret["chainId"] = chain_id;

    member_to_json(ret, "homesteadBlock", homestead_block);
    member_to_json(ret, "eip150Block", tangerine_whistle_block);
    member_to_json(ret, "eip155Block", spurious_dragon_block);
    member_to_json(ret, "byzantiumBlock", byzantium_block);
    member_to_json(ret, "constantinopleBlock", constantinople_block);
    member_to_json(ret, "petersburgBlock", petersburg_block);
    member_to_json(ret, "istanbulBlock", istanbul_block);
    member_to_json(ret, "muirGlacierBlock", muir_glacier_block);
    member_to_json(ret, "daoForkBlock", dao_block);
    member_to_json(ret, "berlinBlock", berlin_block);

    return ret;
}

bool operator==(const ChainConfig& a, const ChainConfig& b) { return a.Json() == b.Json(); }
std::ostream& operator<<(std::ostream& out, const ChainConfig& obj) { return out << obj.Json().dump(); }

}  // namespace silkworm
