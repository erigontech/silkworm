/*
   Copyright 2021-2022 The Silkworm Authors

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

#include "identity.hpp"

namespace silkworm {

// TODO (Andrew) what about terminal total difficulty?

std::vector<BlockNum> ChainIdentity::distinct_fork_numbers() const {
    std::vector<BlockNum> forks;

    for (std::optional<uint64_t> bn : config.evmc_fork_blocks) {
        if (bn && *bn != 0) {
            forks.push_back(*bn);
        }
    }
    if (config.dao_block) {
        forks.push_back(*config.dao_block);
    }
    if (config.muir_glacier_block) {
        forks.push_back(*config.muir_glacier_block);
    }
    if (config.arrow_glacier_block) {
        forks.push_back(*config.arrow_glacier_block);
    }
    if (config.gray_glacier_block) {
        forks.push_back(*config.gray_glacier_block);
    }

    sort(forks.begin(), forks.end());                              // block list must be ordered
    forks.erase(unique(forks.begin(), forks.end()), forks.end());  // do not repeat block if 2 forks overlap

    return forks;
}

}  // namespace silkworm
