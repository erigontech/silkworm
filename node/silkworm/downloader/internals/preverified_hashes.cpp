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

#include "preverified_hashes.hpp"

extern const uint64_t* preverified_hashes_mainnet_data();
extern size_t sizeof_preverified_hashes_mainnet_data();
extern uint64_t preverified_hashes_mainnet_height();

namespace silkworm {

static std::pair<uint64_t, std::set<evmc::bytes32>> load_preverified_hashes_mainnet() {

    std::pair<uint64_t, std::set<evmc::bytes32>> ret{0,{}};
    auto data_size{sizeof_preverified_hashes_mainnet_data()};
    if(data_size) {
        auto data_ptr{reinterpret_cast<const evmc::bytes32*>(preverified_hashes_mainnet_data())};
        auto num_els{data_size / sizeof(evmc::bytes32)};
        for (uint64_t i = 0; i < num_els; ++i) {
            ret.second.insert(data_ptr[i]);
        }
        ret.first = preverified_hashes_mainnet_height();
    }
    return ret;
}

const std::pair<uint64_t, std::set<evmc::bytes32>> get_preverified_hashes(uint64_t chain_id) {

    switch (chain_id) {
        case 1:
            return load_preverified_hashes_mainnet();
        default:
            return {0, {}};
    };
}

}  // namespace silkworm