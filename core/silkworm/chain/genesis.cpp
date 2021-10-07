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

#include "genesis.hpp"

#include <cassert>
#include <stdexcept>

extern const char* genesis_mainnet_data();
extern size_t sizeof_genesis_mainnet_data();

extern const char* genesis_goerli_data();
extern size_t sizeof_genesis_goerli_data();

extern const char* genesis_rinkeby_data();
extern size_t sizeof_genesis_rinkeby_data();

namespace silkworm {

std::string read_genesis_data(uint64_t chain_id) {
    std::string ret{};
    switch (chain_id) {
        case 1:
            assert(sizeof_genesis_mainnet_data() != 0);
            ret.assign(genesis_mainnet_data(), sizeof_genesis_mainnet_data());
            break;
        case 4:
            assert(sizeof_genesis_rinkeby_data() != 0);
            ret.assign(genesis_rinkeby_data(), sizeof_genesis_rinkeby_data());
            break;
        case 5:
            assert(sizeof_genesis_goerli_data() != 0);
            ret.assign(genesis_goerli_data(), sizeof_genesis_goerli_data());
            break;
        default:
            ret = "{";  // <- Won't be lately parsed as valid json value
    }

    return ret;
}

}  // namespace silkworm
